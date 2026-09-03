using System.Diagnostics;
using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Ports.Platform;
using UserSvc.Infrastructure.Persistence;
using UserSvc.Infrastructure.Persistence.Repositories;
using UserSvc.Infrastructure.Tasks;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>
/// A worker pod: a real <see cref="IHost"/> running the real <see cref="TaskQueueRunner"/> and
/// <see cref="TaskQueueReclaimer"/> over the fixture's real PostgreSQL, with a handler registered
/// through the real <c>AddTaskHandler&lt;T&gt;()</c>.
/// <para>
/// <b>Why a host of its own rather than the API host.</b> The property that matters most about this
/// queue is that N pods can poll one queue and no row reaches two workers, and one API host can
/// only ever run one runner loop per queue - so a single host cannot exercise
/// <c>FOR UPDATE SKIP LOCKED</c> at all. Several of these, sharing the fixture's database, are N
/// pods. They are also cheap enough to start four of: no Kestrel, no OpenIddict, no Redis, no
/// middleware pipeline - just the DbContext, the queue port and the two hosted services, which is
/// exactly the set a worker deployment needs (decision 02's second deployment shape).
/// <see cref="TaskQueueWorkerTests.TheRealApiHostRunsAQueuedTaskThroughTheHandlerCeremony"/> covers
/// the other half - that Program.cs's own wiring reaches the same place - so nothing here rests on
/// this host resembling the API host by luck.
/// </para>
/// <para>
/// <b>The DbContext is registered exactly as <c>AddUserSvcInfrastructure</c> registers it</b>,
/// <c>EnableRetryOnFailure</c> included, because that retrying execution strategy is the seam a
/// handler's transaction has to be opened through (stage 1's contract, item 3). A test host built
/// without it would let a handler do something the real service refuses.
/// </para>
/// <para>
/// Scope validation is switched on deliberately: a <see cref="BackgroundService"/> is a singleton
/// and <see cref="ITaskQueue"/> is scoped, so a runner that injected the port directly rather than
/// creating a scope per poll would fail to build here rather than in production.
/// </para>
/// </summary>
internal sealed class TaskWorkerHost : IAsyncDisposable
{
    private readonly IHost _host;
    private bool _stopped;

    private TaskWorkerHost(IHost host, LogCapture logs)
    {
        _host = host;
        Logs = logs;
    }

    /// <summary>Everything this pod logged. The only place the kill switch and the
    /// handler-exception decision are observable.</summary>
    public LogCapture Logs { get; }

    /// <summary>
    /// Builds a worker pod. Nothing runs until <see cref="StartAsync()"/>.
    /// </summary>
    /// <param name="fixture">The fixture whose PostgreSQL this pod works against.</param>
    /// <param name="journal">The record of what its handler did. Pass one instance to several pods
    /// to pool their deliveries.</param>
    /// <param name="settings">
    /// <c>Tasks:*</c> overrides. The defaults below are the shipped defaults with three
    /// deliberate exceptions, so a test that says nothing gets a pod that works.
    /// </param>
    /// <returns>The unstarted pod.</returns>
    public static TaskWorkerHost Create(
        ServiceFixture fixture,
        TaskJournal journal,
        IReadOnlyDictionary<string, string>? settings = null)
    {
        ArgumentNullException.ThrowIfNull(fixture);
        ArgumentNullException.ThrowIfNull(journal);

        var configuration = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["ConnectionStrings:Default"] = fixture.PostgresConnectionString,

            // The kill switch, off. A test about the switch itself sets it back to 0 - and one
            // does, because "the shipped default claims nothing" has to be proven rather than
            // assumed.
            ["Tasks:WorkerCount"] = "1",

            // The shipped intervals are 2 s and 10 s, which are right for a pod that will run for
            // weeks and wrong for a test that has to observe two polls. Everything these tests
            // assert is about what a poll does, never about how long the wait between two of them
            // is: stage 2's unit tests pin the interval choice against a fake clock, where waiting
            // is free.
            ["Tasks:ShortPollInterval"] = "00:00:00.050",
            ["Tasks:LongPollInterval"] = "00:00:00.100",
        };

        if (settings is not null)
        {
            foreach (var (key, value) in settings)
            {
                configuration[key] = value;
            }
        }

        var logs = new LogCapture();

        // The empty builder, not the default one: no environment variables, no appsettings.json, no
        // user secrets. A machine with Tasks__WorkerCount set for any other reason cannot then
        // change what these tests measure, and the configuration above is the whole of what this
        // pod is configured with.
        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings
        {
            ApplicationName = "usersvc-task-worker",
        });

        builder.Configuration.AddInMemoryCollection(configuration);

        builder.Logging.AddProvider(logs);
        builder.Logging.SetMinimumLevel(LogLevel.Debug);

        builder.ConfigureContainer(new DefaultServiceProviderFactory(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        }));

        builder.Services.AddDbContext<UserSvcDbContext>(options => options
            .UseNpgsql(fixture.PostgresConnectionString, npgsql => npgsql.EnableRetryOnFailure())
            .UseSnakeCaseNamingConvention());

        // The two ports a handler is entitled to. The outbox interceptor the real registration also
        // installs is deliberately absent: it drains domain events at SaveChanges time and nothing
        // on this path calls SaveChanges - every queue operation issues its own statement.
        builder.Services.AddScoped<ITaskQueue, TaskQueueRepository>();
        builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();

        builder.Services.AddSingleton(journal);

        builder.Services.AddTaskQueueWorkers(builder.Configuration);
        builder.Services.AddTaskHandler<JournalTaskHandler>();

        return new TaskWorkerHost(builder.Build(), logs);
    }

    /// <summary>Builds and starts a worker pod.</summary>
    /// <param name="fixture">The fixture whose PostgreSQL this pod works against.</param>
    /// <param name="journal">The record of what its handler did.</param>
    /// <param name="settings"><c>Tasks:*</c> overrides.</param>
    /// <returns>The started pod.</returns>
    public static async Task<TaskWorkerHost> StartAsync(
        ServiceFixture fixture,
        TaskJournal journal,
        IReadOnlyDictionary<string, string>? settings = null)
    {
        var host = Create(fixture, journal, settings);
        await host.StartAsync();

        return host;
    }

    /// <summary>Starts the host, which is what starts the poll loop and the reclaim.</summary>
    /// <returns>A task that completes once both hosted services have been started.</returns>
    public Task StartAsync() => _host.StartAsync();

    /// <summary>
    /// Stops the pod the way SIGTERM does, and reports how long it took.
    /// <para>
    /// The elapsed time is the assertion in the drain test: a stop that returns instantly while a
    /// task is still running is a stop that abandoned it.
    /// </para>
    /// </summary>
    /// <returns>How long the stop took.</returns>
    public async Task<TimeSpan> StopAsync()
    {
        var started = Stopwatch.GetTimestamp();
        await _host.StopAsync();
        _stopped = true;

        return Stopwatch.GetElapsedTime(started);
    }

    /// <summary>A failure message carrying everything this pod knows: its log and its journal
    /// state.</summary>
    /// <param name="journal">The journal to describe alongside the log.</param>
    /// <returns>The formatted diagnostic.</returns>
    public string Diagnose(TaskJournal journal)
    {
        ArgumentNullException.ThrowIfNull(journal);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"The journal saw {journal.Describe()}.{Environment.NewLine}{Logs.Dump()}");
    }

    public async ValueTask DisposeAsync()
    {
        if (!_stopped)
        {
            await _host.StopAsync();
        }

        _host.Dispose();
    }
}
