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
/// </summary>
public sealed class WechatMiniAccessTokenCache(
    IConnectionMultiplexer connection,
    IOptions<RedisOptions> redisOptions,
    ILogger<WechatMiniAccessTokenCache> logger)
{
    private const string CacheKeySuffix = "wechat_mini:access_token";

    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private readonly string _key = redisOptions.Value.KeyPrefix + CacheKeySuffix;

    private string _token = string.Empty;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;

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

            _token = token;
            _expiresAt = now + ttl;

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
        _token = string.Empty;
        _expiresAt = DateTimeOffset.MinValue;

        try
        {
            await connection.GetDatabase().KeyDeleteAsync(_key).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            logger.LogWarning(
                ex, "Could not drop the cached WeChat mini-program access token from Redis.");
        }
    }

    private string TryRead(DateTimeOffset now) => _token.Length > 0 && now < _expiresAt ? _token : string.Empty;

    private async Task<string> TryReadRedisAsync()
    {
        try
        {
            var value = await connection.GetDatabase().StringGetAsync(_key).ConfigureAwait(false);
            return value.IsNullOrEmpty ? string.Empty : value.ToString();
        }
        catch (Exception ex) when (IsRedisFailure(ex))
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
                .StringSetAsync(_key, token, expiry: ttl, keepTtl: false, when: When.Always, flags: CommandFlags.None)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            logger.LogWarning(ex, "Could not share the WeChat mini-program access token through Redis.");
        }
    }

    /// <summary>
    /// The StackExchange.Redis hierarchy is not what it looks like: <c>RedisTimeoutException</c>
    /// derives from <see cref="TimeoutException"/> and <c>RedisCommandException</c> straight from
    /// <see cref="Exception"/>, so catching <c>RedisException</c> alone misses every timeout.
    /// </summary>
    private static bool IsRedisFailure(Exception ex) =>
        ex is RedisException or RedisTimeoutException or RedisCommandException;
}
