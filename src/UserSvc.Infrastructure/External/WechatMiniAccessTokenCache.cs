using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using UserSvc.Infrastructure.Platform;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The mini program's global access token, cached.
/// <para>
/// <b>Caching is not an optimisation here, it is a correctness requirement.</b> The token is global
/// per mini program and WeChat rate limits how often it may be fetched; a per-request fetch trips
/// that limit under any real traffic and then nothing works at all.
/// </para>
/// <para>
/// <b>Two layers, and Redis is the soft one.</b> Redis is consulted first so every replica shares
/// one token, but a Redis outage degrades to a per-process token rather than failing: the worst
/// case is one fetch per replica instead of one per fleet, which the stable-token endpoint
/// tolerates. Fail-closed here would take WeChat mini-program sign-in down for a cache.
/// </para>
/// <para>
/// <b>Concurrent refreshes are collapsed into one.</b> A cold start with a hundred simultaneous
/// sign-ins must produce one call to WeChat, not a hundred - the semaphore plus the re-check inside
/// it is what guarantees the ninety-nine that queued behind the winner take its answer instead of
/// racing it.
/// </para>
/// <para>
/// Registered as a singleton: the in-process half of the cache and the semaphore are the state, and
/// a scoped instance would hold neither across requests.
/// </para>
/// <para>
/// <b><see cref="LionTravelAccessTokenCache"/> is deliberately this class again</b> rather than a
/// shared base class: the two cache different upstreams' tokens under different keys, and the day
/// one of them needs a different failure direction, shared code is what would make that change
/// dangerous. The cost is that a correctness fix has to be made twice - so the two are kept
/// line-for-line recognisable, and <c>AccessTokenCacheTests</c> runs every case against both.
/// </para>
/// </summary>
public sealed class WechatMiniAccessTokenCache(
    IConnectionMultiplexer connection,
    IOptions<RedisOptions> redisOptions,
    ILogger<WechatMiniAccessTokenCache> logger)
{
    private const string CacheKeySuffix = "wechat_mini:access_token";

    private readonly SemaphoreSlim _refreshGate = new(1, 1);

    /// <summary>The in-process half of the cache. Swapped, never mutated in place - see
    /// <see cref="CachedToken"/>.</summary>
    private CachedToken _cached = CachedToken.None;

    /// <summary>
    /// The Redis key, read at the point of use rather than in a field initializer.
    /// <para>
    /// A field initializer runs in the constructor, so reading
    /// <see cref="IOptions{TOptions}.Value"/> there makes merely <i>constructing</i> this cache
    /// throw on a deployment whose Redis section will not validate - the failure mode
    /// docs/architecture.md records, and one that would take this singleton's whole dependency
    /// graph with it. Today <c>RedisOptions</c> is validated at startup so the host would refuse
    /// to boot first; the point is not to leave the shape lying around for the day that changes.
    /// </para>
    /// </summary>
    private string Key => redisOptions.Value.KeyPrefix + CacheKeySuffix;

    /// <param name="forceRefresh">
    /// Skip both cache layers. Set only after WeChat has rejected a token this cache handed out -
    /// see <see cref="WechatMiniHttpClient"/> - never speculatively, or the rate limit the cache
    /// exists for comes straight back.
    /// </param>
    /// <param name="fetch">Fetches a fresh token and reports how long it may be cached.</param>
    /// <param name="now">Current time, so the in-process expiry is not read from the ambient clock.</param>
    /// <param name="cancellationToken">Cancels the wait for the refresh gate and the fetch.</param>
    public async Task<string> GetAsync(
        bool forceRefresh,
        Func<CancellationToken, Task<(string Token, TimeSpan Ttl)>> fetch,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fetch);

        if (!forceRefresh && TryRead(now) is { Length: > 0 } cached)
        {
            return cached;
        }

        if (!forceRefresh && await TryReadRedisAsync() is { Length: > 0 } shared)
        {
            return shared;
        }

        await _refreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Re-checked inside the gate: everyone who queued while the winner was fetching would
            // otherwise fetch again the moment they were let through, which is the stampede the
            // gate is here to prevent.
            if (!forceRefresh && TryRead(now) is { Length: > 0 } refreshed)
            {
                return refreshed;
            }

            var (token, ttl) = await fetch(cancellationToken).ConfigureAwait(false);

            Volatile.Write(ref _cached, new CachedToken(token, now + ttl));

            await TryWriteRedisAsync(token, ttl).ConfigureAwait(false);

            return token;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    /// <summary>
    /// Drops both layers after WeChat rejected the cached token. Best effort on the Redis half: the
    /// in-process copy is already gone, and a stale shared copy costs one more retry rather than a
    /// failure.
    /// </summary>
    public async Task InvalidateAsync()
    {
        Volatile.Write(ref _cached, CachedToken.None);

        try
        {
            await connection.GetDatabase().KeyDeleteAsync(Key).ConfigureAwait(false);
        }
        catch (Exception ex) when (RedisFailure.IsStoreFailure(ex, CancellationToken.None))
        {
            logger.LogWarning(
                ex, "Could not drop the cached WeChat mini-program access token from Redis.");
        }
    }

    /// <summary>
    /// The in-process copy, if there is one that is still good. One read of one reference, so the
    /// token and the expiry that authorises it are always the same refresh's.
    /// </summary>
    private string TryRead(DateTimeOffset now)
    {
        var cached = Volatile.Read(ref _cached);

        return cached.Token.Length > 0 && now < cached.ExpiresAt ? cached.Token : string.Empty;
    }

    /// <summary>
    /// A token and the instant it stops being usable, as <b>one</b> object.
    /// <para>
    /// Two fields could not be read as a pair: a reader outside the refresh gate could take the
    /// token from one refresh and the expiry from the next, and a
    /// <see cref="DateTimeOffset"/> is sixteen bytes, so it is not even read atomically by itself -
    /// a reader could see an instant that was never written. Both are answered by making the pair a
    /// single immutable reference that a refresh swaps in one assignment: a reader sees the state
    /// entirely before or entirely after, and there is no third possibility to reason about.
    /// </para>
    /// </summary>
    /// <param name="Token">The cached token, or empty when there is none.</param>
    /// <param name="ExpiresAt">When it stops being usable. Past for an empty token.</param>
    private sealed record CachedToken(string Token, DateTimeOffset ExpiresAt)
    {
        /// <summary>No token: the state before the first mint and after an invalidation.</summary>
        public static readonly CachedToken None = new(string.Empty, DateTimeOffset.MinValue);
    }

    private async Task<string> TryReadRedisAsync()
    {
        try
        {
            var value = await connection.GetDatabase().StringGetAsync(Key).ConfigureAwait(false);
            return value.IsNullOrEmpty ? string.Empty : value.ToString();
        }
        catch (Exception ex) when (RedisFailure.IsStoreFailure(ex, CancellationToken.None))
        {
            logger.LogWarning(
                ex, "Could not read the shared WeChat mini-program access token; falling back to a local one.");

            return string.Empty;
        }
    }

    private async Task TryWriteRedisAsync(string token, TimeSpan ttl)
    {
        try
        {
            await connection.GetDatabase()
                .StringSetAsync(Key, token, expiry: ttl, keepTtl: false, when: When.Always, flags: CommandFlags.None)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (RedisFailure.IsStoreFailure(ex, CancellationToken.None))
        {
            logger.LogWarning(ex, "Could not share the WeChat mini-program access token through Redis.");
        }
    }

}
