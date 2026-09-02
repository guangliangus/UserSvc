using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using StackExchange.Redis;
using Testcontainers.PostgreSql;
using Testcontainers.Redis;
using UserSvc.Domain.Users;
using UserSvc.Infrastructure.Persistence;
using Xunit;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>
/// One PostgreSQL container, one Redis container and one hosted copy of the API for the whole
/// assembly. Roughly three seconds of container startup, paid once.
/// <para>
/// It short-circuits on the same probe <see cref="RequiresDockerFactAttribute"/> uses. xunit
/// constructs a collection fixture and awaits <see cref="InitializeAsync"/> even when every test
/// in the collection is skipped, so without that check a machine without Docker would sit through
/// the full Docker connect timeout in order to run nothing.
/// </para>
/// </summary>
public sealed class ServiceFixture : IAsyncLifetime
{
    private const string DatabaseName = "usersvc";
    private const string DatabaseUser = "usersvc";
    private const string DatabasePassword = "usersvc";

    /// <summary>The service runs against PostgreSQL 18 in development; the test container matches it,
    /// because "the partial index behaves like this" is only worth asserting on the real version.</summary>
    private const string PostgresImage = "postgres:18";

    private const string RedisImage = "redis:8-alpine";

    private PostgreSqlContainer? _postgres;
    private RedisContainer? _redis;
    private UserSvcApplicationFactory? _factory;
    private ConnectionMultiplexer? _redisProbe;
    private string _truncateStatement = string.Empty;

    /// <summary>Whether the containers actually started. False only when Docker is absent, in which
    /// case every test in the collection is skipped at discovery.</summary>
    public bool IsRunning => _factory is not null;

    /// <summary>Connection string of the throwaway database, for assertions that want to see the
    /// rows the service wrote rather than what an ORM says about them.</summary>
    public string PostgresConnectionString { get; private set; } = string.Empty;

    /// <summary>Configuration string of the throwaway Redis, so a second host can be pointed at
    /// the same instance.</summary>
    public string RedisConfiguration { get; private set; } = string.Empty;

    /// <summary>The hosted service's own container. Resolving <c>IOptions</c> or a repository from
    /// here reads exactly what the running API is using.</summary>
    public IServiceProvider Services => Factory.Services;

    /// <summary>A second Redis connection owned by the tests, with admin commands enabled so state
    /// can be flushed between tests. The service's own multiplexer deliberately does not allow them.</summary>
    public IConnectionMultiplexer RedisProbe =>
        _redisProbe ?? throw new InvalidOperationException(FixtureNotStarted);

    private const string FixtureNotStarted =
        "The integration fixture never started because Docker was unavailable. Tests that need it "
        + "must be marked [RequiresDockerFact] so they are skipped at discovery instead.";

    private UserSvcApplicationFactory Factory =>
        _factory ?? throw new InvalidOperationException(FixtureNotStarted);

    public async Task InitializeAsync()
    {
        if (!DockerAvailability.IsAvailable)
        {
            return;
        }

        // The image-taking overload: the parameterless PostgreSqlBuilder()/RedisBuilder() are
        // [Obsolete] at 4.14.0, and CS0618 is an error in this repository.
        _postgres = new PostgreSqlBuilder(PostgresImage)
            .WithDatabase(DatabaseName)
            .WithUsername(DatabaseUser)
            .WithPassword(DatabasePassword)
            .Build();

        _redis = new RedisBuilder(RedisImage).Build();

        // No explicit wait strategy: PostgreSqlBuilder already installs a pg_isready one and the
        // Redis module installs its own.
        await Task.WhenAll(_postgres.StartAsync(), _redis.StartAsync());

        PostgresConnectionString = _postgres.GetConnectionString();
        RedisConfiguration = _redis.GetConnectionString();

        await ApplySchemaAsync();
        _truncateStatement = await BuildTruncateStatementAsync();

        var redisOptions = ConfigurationOptions.Parse(RedisConfiguration);
        redisOptions.AllowAdmin = true;
        _redisProbe = await ConnectionMultiplexer.ConnectAsync(redisOptions);

        _factory = new UserSvcApplicationFactory(PostgresConnectionString, RedisConfiguration);

        // Forces the host to build and start, which is what runs FirstPartyClientSeeder. Doing it
        // here rather than lazily inside the first test keeps that cost out of one arbitrary
        // test's timing.
        using var warmUp = _factory.CreateClient();
    }

    public async Task DisposeAsync()
    {
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }

        if (_redisProbe is not null)
        {
            await _redisProbe.DisposeAsync();
        }

        if (_redis is not null)
        {
            await _redis.DisposeAsync();
        }

        if (_postgres is not null)
        {
            await _postgres.DisposeAsync();
        }
    }

    /// <summary>
    /// Wipe every table between tests. The list is read from <c>pg_tables</c> rather than hard
    /// coded, because a hard-coded list rots the first time someone adds a table and the symptom is
    /// a test that fails only when it runs second.
    /// </summary>
    public async Task ResetAsync()
    {
        if (!IsRunning)
        {
            return;
        }

        await using var connection = new NpgsqlConnection(PostgresConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(_truncateStatement, connection);
        await command.ExecuteNonQueryAsync();

        foreach (var endpoint in RedisProbe.GetEndPoints())
        {
            await RedisProbe.GetServer(endpoint).FlushDatabaseAsync();
        }
    }

    /// <summary>An HTTP client with no credentials at all.</summary>
    public HttpClient CreateClient() => Factory.CreateClient();

    /// <summary>
    /// A <b>second</b> host over the same containers, configured differently. The caller owns it
    /// and must dispose it.
    /// <para>
    /// It exists for one kind of test: proving that a deployment missing a capability's
    /// configuration still serves everything else. That claim cannot be made from a request - it is
    /// a property of a host - and it is the rule docs/architecture.md records having been broken
    /// three times, so it is worth being able to state.
    /// </para>
    /// <para>
    /// Sharing the containers is safe and deliberate: the reset between tests is the same one, the
    /// first-party client seeder re-applies the same descriptor on every boot rather than inserting
    /// a second row, and the two hosts are never asked to serve the same request. What is not safe
    /// is holding one open across tests, which is why it is not cached here.
    /// </para>
    /// </summary>
    /// <param name="overrides">Host settings to override, applied last so they win.</param>
    /// <param name="peerAddress">
    /// A client address to stamp on every request this host serves, or null for the default -
    /// which is no address at all, because that is what <c>TestServer</c> gives a connection it
    /// never made. Every per-source rate-limit budget in the service disables itself when there is
    /// no address to attribute to, so this is what a test about one has to ask for.
    /// </param>
    internal UserSvcApplicationFactory CreateHost(
        IReadOnlyDictionary<string, string> overrides, string? peerAddress = null)
    {
        ArgumentNullException.ThrowIfNull(overrides);

        if (!IsRunning)
        {
            throw new InvalidOperationException(FixtureNotStarted);
        }

        return new UserSvcApplicationFactory(
            PostgresConnectionString, RedisConfiguration, overrides, peerAddress);
    }

    /// <summary>
    /// An HTTP client carrying the Development header identity. It exercises the same pipeline a
    /// bearer token does - authorization, the revoked-session middleware, the error contract - and
    /// skips only the token issuance, which the auth-flow tests cover with real tokens.
    /// </summary>
    public HttpClient CreateDevClient(int userId, string sessionId = "dev-session")
    {
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Dev-User-Id", userId.ToString(CultureInfo.InvariantCulture));
        client.DefaultRequestHeaders.Add("X-Dev-Session-Id", sessionId);
        return client;
    }

    /// <summary>A scope over the running host's container, for the tests that drive EF and the
    /// unit of work directly instead of through HTTP.</summary>
    public AsyncServiceScope CreateScope() => Services.CreateAsyncScope();

    /// <summary>A connection the test owns, used where a second transaction has to be held open on
    /// purpose - the optimistic-concurrency race, for instance.</summary>
    public NpgsqlConnection CreateConnection() => new(PostgresConnectionString);

    /// <summary>Insert a user straight into the table. Timestamps are UTC because Npgsql writes a
    /// <c>DateTimeOffset</c> to <c>timestamptz</c> only when its offset is zero.</summary>
    public async Task<int> SeedUserAsync(string status = UserStatuses.Active, string nickname = "seed")
    {
        await using var scope = CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<UserSvcDbContext>();

        var now = DateTimeOffset.UtcNow;
        var user = new User
        {
            Status = status,
            Nickname = nickname,
            FirstName = "Seed",
            LastName = "User",
            ResidenceCountryCode = "TW",
            CreatedAt = now,
            UpdatedAt = now,
        };

        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user.Id;
    }

    public async Task ExecuteAsync(string sql, params object[] arguments)
    {
        await using var connection = new NpgsqlConnection(PostgresConnectionString);
        await connection.OpenAsync();
        await using var command = Command(connection, sql, arguments);
        await command.ExecuteNonQueryAsync();
    }

    public async Task<long> CountAsync(string sql, params object[] arguments)
    {
        await using var connection = new NpgsqlConnection(PostgresConnectionString);
        await connection.OpenAsync();
        await using var command = Command(connection, sql, arguments);
        return Convert.ToInt64(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Runs a statement whose first column is an integer and returns it - an
    /// <c>INSERT ... RETURNING id</c>, in practice.
    /// <para>
    /// It exists because <c>iam</c> is deliberately outside the between-tests truncation (see
    /// <see cref="BuildTruncateStatementAsync"/>), so its serial ids climb across the assembly and
    /// no seed may assume a literal one. Reading the id back is the only honest way to name the row
    /// that was just written.
    /// </para>
    /// </summary>
    public async Task<int> InsertReturningIdAsync(string sql, params object[] arguments)
    {
        await using var connection = new NpgsqlConnection(PostgresConnectionString);
        await connection.OpenAsync();
        await using var command = Command(connection, sql, arguments);

        return Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    /// <summary>Reads a single-column result set as strings. Nulls come back as the empty string,
    /// which is what every column this suite reads is declared NOT NULL DEFAULT '' as anyway.</summary>
    public async Task<IReadOnlyList<string>> QueryStringsAsync(string sql, params object[] arguments)
    {
        await using var connection = new NpgsqlConnection(PostgresConnectionString);
        await connection.OpenAsync();
        await using var command = Command(connection, sql, arguments);
        await using var reader = await command.ExecuteReaderAsync();

        var rows = new List<string>();
        while (await reader.ReadAsync())
        {
            rows.Add(reader.IsDBNull(0) ? string.Empty : reader.GetValue(0).ToString() ?? string.Empty);
        }

        return rows;
    }

    private static NpgsqlCommand Command(NpgsqlConnection connection, string sql, object[] arguments)
    {
        var command = new NpgsqlCommand(sql, connection);
        for (var i = 0; i < arguments.Length; i++)
        {
            command.Parameters.AddWithValue(
                string.Create(CultureInfo.InvariantCulture, $"p{i}"), arguments[i]);
        }

        return command;
    }

    /// <summary>
    /// Applies db/*.sql in filename order through Npgsql rather than
    /// <c>PostgreSqlContainer.ExecScriptAsync</c>. That helper shells out to psql <b>without</b>
    /// <c>-v ON_ERROR_STOP=1</c>, so a broken statement still returns exit code 0 and the failure
    /// resurfaces as "relation does not exist" three tests later. NpgsqlCommand throws
    /// <c>PostgresException</c> on the first failing statement, naming it.
    /// </summary>
    private async Task ApplySchemaAsync()
    {
        await using var connection = new NpgsqlConnection(PostgresConnectionString);
        await connection.OpenAsync();

        var scripts = Directory
            .EnumerateFiles(Path.Combine(RepositoryRoot(), "db"), "*.sql")
            .OrderBy(path => Path.GetFileName(path), StringComparer.Ordinal)
            .ToList();

        if (scripts.Count == 0)
        {
            throw new InvalidOperationException("No db/*.sql scripts were found; the schema would be empty.");
        }

        foreach (var script in scripts)
        {
            await using var command = new NpgsqlCommand(await File.ReadAllTextAsync(script), connection);
            await command.ExecuteNonQueryAsync();
        }
    }

    /// <summary>
    /// RESTART IDENTITY is not optional: without it the serial ids climb across tests, and any
    /// assertion naming a literal id silently becomes order-dependent.
    /// <para>
    /// <c>openiddict_applications</c> is the one deliberate exclusion. The first-party client is
    /// seeded once, by a hosted service at host startup; truncating it would turn every token
    /// request after the first test into <c>invalid_client</c>.
    /// </para>
    /// <para>
    /// The <c>iam</c> schema is included <b>selectively</b>, by name, and the list is the point.
    /// Its runtime tables - accounts, their login identities, tenant memberships, role bindings and
    /// the audit trail - have to go, or a back-office test cannot reuse an address (the partial
    /// unique index on an ACTIVE e-mail identity refuses it) and "no audit row was written" is
    /// unanswerable. Its catalogue tables - menus, permissions, roles and the two grant tables -
    /// have to stay: they are contract data applied once by <c>db/0007_iam_seed.sql</c> at fixture
    /// start, so truncating them would leave every role binding pointing at nothing and every
    /// permission check refusing, from the second test onwards. A wildcard over the schema cannot
    /// tell those two sets apart, which is why this one is spelled out.
    /// </para>
    /// </summary>
    private async Task<string> BuildTruncateStatementAsync()
    {
        await using var connection = new NpgsqlConnection(PostgresConnectionString);
        await connection.OpenAsync();

        await using var command = new NpgsqlCommand(
            """
            SELECT quote_ident(schemaname) || '.' || quote_ident(tablename)
            FROM pg_tables
            WHERE (schemaname IN ('identity', 'openiddict')
                   AND NOT (schemaname = 'openiddict' AND tablename = 'openiddict_applications'))
               OR (schemaname = 'iam'
                   AND tablename IN ('backend_users', 'backend_identities', 'tenant_members',
                                     'user_tenant_roles', 'iam_audit_logs'))
            ORDER BY 1
            """,
            connection);

        var tables = new List<string>();
        await using (var reader = await command.ExecuteReaderAsync())
        {
            while (await reader.ReadAsync())
            {
                tables.Add(reader.GetString(0));
            }
        }

        if (tables.Count == 0)
        {
            throw new InvalidOperationException(
                "The schema scripts created no tables, so the reset between tests would be a no-op.");
        }

        return $"TRUNCATE TABLE {string.Join(", ", tables)} RESTART IDENTITY CASCADE;";
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "UserSvc.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
               ?? throw new InvalidOperationException("Could not locate the repository root (UserSvc.slnx).");
    }
}
