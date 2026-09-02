using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Infrastructure.Platform;

/// <summary>
/// One account's authority surface as it is cached, which is a little more than the port hands
/// back. <see cref="Ver"/> is the account's <c>token_version</c> at the moment the entry was
/// computed, and it is the only field a reader compares: an entry older than the version the
/// presented token was minted against is a stale backfill that raced an invalidation, and must not
/// be served to a token that has already lived past it.
/// </summary>
/// <param name="Ver">The <c>iam.backend_users.token_version</c> the entry was computed from.</param>
/// <param name="Roles">Role codes.</param>
/// <param name="Permissions">Permission codes.</param>
/// <param name="Menus">Menu codes.</param>
/// <param name="Scopes">Data breadth per tenant dimension; both dimensions always present.</param>
public sealed record CachedAuthzSnapshot(
    int Ver,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> Menus,
    IReadOnlyDictionary<string, ScopeClaim> Scopes);

/// <summary>
/// The authority-snapshot cache on Redis, shared by the provider that fills it and the two ports
/// that empty it.
/// <para>
/// <b>Every operation fails soft, and that is the whole design.</b> The database is authoritative;
/// this is a five-minute memo. A failed read recomputes, a failed write means the next request
/// recomputes, and a failed invalidation means the entry lives out its TTL - the worst case is one
/// stale authority face for at most <see cref="Ttl"/>, and the token-version comparison catches the
/// case that actually matters. Throwing on any of them would turn a Redis blip into a back office
/// that cannot authorize anybody.
/// </para>
/// <para>
/// Keys are <c>{prefix}authz:{userId}:{actType}:{actCode}:{actDim}</c> with fixed placeholders for
/// the empty segments, so the shape never varies. Each user also gets an index SET naming their
/// live entries, because invalidation has to find every context an account has entered and
/// <c>SCAN</c> over a shared keyspace is both slow and rude. The set is small - one member per
/// context the account has actually used - and is deleted along with the entries it names.
/// </para>
/// <para>
/// Exception handling matches <see cref="RedisSessionRevocationStore"/>: StackExchange.Redis puts
/// timeouts under <see cref="TimeoutException"/> and command errors under <see cref="Exception"/>,
/// so catching <c>RedisException</c> alone would miss exactly the failures this class exists to
/// absorb.
/// </para>
/// </summary>
public sealed class RedisAuthzSnapshotCache(
    IConnectionMultiplexer connection,
    IOptions<RedisOptions> options,
    ILogger<RedisAuthzSnapshotCache> logger)
{
    /// <summary>Five minutes, matching the contract. It is the ceiling on how stale an authority
    /// face can be when an invalidation is lost, so it is short by design.</summary>
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly string _keyPrefix = options.Value.KeyPrefix;

    /// <summary>The entry key for one account in one acting context.</summary>
    public string KeyFor(int userId, ActClaim act)
    {
        ArgumentNullException.ThrowIfNull(act);

        var code = string.IsNullOrEmpty(act.Code) ? "*" : act.Code;
        var dimension = string.IsNullOrEmpty(act.Dimension) ? "-" : act.Dimension;

        return $"{_keyPrefix}authz:{userId}:{act.Type}:{code}:{dimension}";
    }

    /// <summary>
    /// Null on a miss, on a read failure and on a corrupt entry alike - all three mean "compute it".
    /// A corrupt entry is evicted on the way out so the next reader gets a clean miss rather than
    /// hitting the same garbage until it expires.
    /// </summary>
    public async Task<CachedAuthzSnapshot?> ReadAsync(string key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        RedisValue raw;
        try
        {
            raw = await connection.GetDatabase().StringGetAsync(key);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            logger.LogWarning(ex, "Authorization snapshot read failed at {Key}; recomputing.", key);
            return null;
        }

        if (raw.IsNullOrEmpty)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<CachedAuthzSnapshot>((string)raw!, Json);
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "Authorization snapshot at {Key} is corrupt; evicting it.", key);
            await DeleteQuietlyAsync(key);
            return null;
        }
    }

    /// <summary>
    /// Best effort. A plain SET rather than SETNX: every writer computed from committed rows, and
    /// the one dangerous interleaving - a pre-bump backfill landing after an invalidation - is
    /// caught by the version comparison on the way back out.
    /// </summary>
    public async Task WriteAsync(
        int userId, string key, CachedAuthzSnapshot snapshot, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var database = connection.GetDatabase();

            await database.StringSetAsync(
                key,
                JsonSerializer.Serialize(snapshot, Json),
                expiry: Ttl,
                keepTtl: false,
                when: When.Always,
                flags: CommandFlags.None);

            // The index is what makes invalidation reachable. If only this half fails the entry
            // still expires on its own; it is simply out of reach until then, which is why the
            // failure is worth a line but not worth undoing the write above.
            await database.SetAddAsync(IndexKeyFor(userId), key);
            await database.KeyExpireAsync(IndexKeyFor(userId), Ttl);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            logger.LogWarning(
                ex, "Authorization snapshot for account {UserId} could not be cached.", userId);
        }
    }

    /// <summary>
    /// Drops every cached context of these accounts. <b>Call it after the change has committed</b>:
    /// deleting inside the transaction window lets a concurrent request refill the entry from rows
    /// that have not committed yet, which is the exact race this is meant to close.
    /// </summary>
    public async Task InvalidateAsync(IReadOnlyCollection<int> userIds, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        foreach (var userId in userIds.Distinct())
        {
            var indexKey = IndexKeyFor(userId);

            try
            {
                var database = connection.GetDatabase();
                var members = await database.SetMembersAsync(indexKey);

                RedisKey[] keys =
                [
                    .. members.Where(member => !member.IsNullOrEmpty).Select(member => new RedisKey(member.ToString())),
                    indexKey,
                ];

                await database.KeyDeleteAsync(keys);
            }
            catch (Exception ex) when (IsRedisFailure(ex))
            {
                // Not an error: the entries expire on their own within the TTL, and the token
                // version bump that accompanies every narrowing change is the real convergence
                // mechanism. This only shortens the window.
                logger.LogWarning(
                    ex,
                    "Cached authorization snapshots for account {UserId} could not be dropped; "
                    + "they will expire within {TtlSeconds} seconds.",
                    userId,
                    Ttl.TotalSeconds);
            }
        }
    }

    private string IndexKeyFor(int userId) => $"{_keyPrefix}authz:idx:{userId}";

    private async Task DeleteQuietlyAsync(string key)
    {
        try
        {
            await connection.GetDatabase().KeyDeleteAsync(key);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            logger.LogWarning(ex, "Corrupt authorization snapshot at {Key} could not be evicted.", key);
        }
    }

    private static bool IsRedisFailure(Exception ex) =>
        ex is RedisException or RedisTimeoutException or RedisCommandException;
}
