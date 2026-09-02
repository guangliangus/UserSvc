using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Infrastructure.Platform;

/// <summary>
/// The revocation set on Redis (decision 11). Keys are <c>{prefix}revoked:sid:{sessionId}</c> and
/// expire with the access token, so the set only ever holds sessions revoked in the last few
/// minutes and never needs a cleanup job.
/// <para>
/// <b>The two operations deliberately handle a Redis failure in opposite directions, and that
/// asymmetry is the subtle part.</b> A failed read fails <i>open</i>: the token has already passed
/// full signature validation and this is only an extra check, with the short access-token lifetime
/// as the fallback, so refusing traffic during a Redis blip would cost far more than it buys — it
/// logs a warning and reports "not revoked". A failed write fails <i>loud</i>: the caller has
/// already committed the database row, so the session is dead on the refresh path either way, but
/// the fast path silently did not take. Swallowing that would leave a signed-out device working
/// for the rest of the access-token lifetime with no signal anywhere, so it throws and the
/// operator learns about it.
/// </para>
/// <para>
/// Exception handling here is written against the real StackExchange.Redis hierarchy, which is not
/// what it looks like: <c>RedisTimeoutException</c> derives from <see cref="TimeoutException"/> and
/// <c>RedisCommandException</c> derives straight from <see cref="Exception"/>. Only
/// <c>RedisConnectionException</c> and <c>RedisServerException</c> are <c>RedisException</c>s, so
/// catching <c>RedisException</c> alone misses every timeout — which is precisely the failure that
/// fail-open exists for.
/// </para>
/// </summary>
public sealed class RedisSessionRevocationStore(
    IConnectionMultiplexer connection,
    IOptions<RedisOptions> options,
    ILogger<RedisSessionRevocationStore> logger) : ISessionRevocationStore
{
    /// <summary>The value is irrelevant — only the key's existence and its TTL carry meaning.</summary>
    private const string Marker = "1";

    /// <summary>
    /// Read at the point of use, never into a field. <c>.Value</c> is where the section's
    /// DataAnnotations run, so binding it into a field initializer makes merely <i>constructing</i>
    /// this type throw when the <c>Redis</c> section is unusable - and it then reports somebody
    /// else's missing setting from every endpoint that shares the object graph
    /// (docs/architecture.md, "a missing capability may only break itself"). <c>.Value</c> is
    /// cached, so reading it per call costs nothing.
    /// </summary>
    private string KeyPrefix => options.Value.KeyPrefix;

    public async Task RevokeAsync(string sessionId, TimeSpan ttl, CancellationToken cancellationToken)
    {
        // No StackExchange.Redis async method accepts a CancellationToken, so the token is honoured
        // at the boundary only. The command itself, once issued, is not cancellable.
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            // Named arguments on purpose: the positional five-argument form binds to a hidden
            // legacy overload with a different meaning for the trailing parameters.
            await connection.GetDatabase().StringSetAsync(
                KeyFor(sessionId),
                Marker,
                expiry: ttl,
                keepTtl: false,
                when: When.Always,
                flags: CommandFlags.None);
        }
        catch (Exception ex) when (RedisFailure.IsStoreFailure(ex, cancellationToken))
        {
            throw RevocationNotRecorded(ex);
        }
    }

    public async Task<bool> IsRevokedAsync(string sessionId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            return await connection.GetDatabase().KeyExistsAsync(KeyFor(sessionId), CommandFlags.None);
        }
        // The FOURTH shape matters most here, of all eight adapters. This read runs on every
        // authenticated request, so an unclassified store failure is not a degraded session check -
        // it is an unhandled exception on the whole authenticated surface, which is the opposite of
        // the fail-open contract this method documents. RedisFailure owns the classification.
        catch (Exception ex) when (RedisFailure.IsStoreFailure(ex, cancellationToken))
        {
            return FailOpen(sessionId, ex);
        }
    }

    private string KeyFor(string sessionId) => $"{KeyPrefix}revoked:sid:{sessionId}";

    private bool FailOpen(string sessionId, Exception cause)
    {
        // Warning, not error: this request is still being served correctly. One line per affected
        // request is the point — the rate is what tells an operator how much traffic is bypassing
        // revocation right now, which a single line at the moment the connection dropped could not.
        logger.LogWarning(
            cause,
            "Redis revocation lookup failed for session {SessionId}; failing open and treating the "
            + "session as not revoked. Access tokens for revoked sessions stay usable until they expire.",
            sessionId);

        return false;
    }

    /// <summary>
    /// 502, not 500: the caller did nothing wrong and the request is not retryable at the
    /// application level. The inner exception carries the Redis failure type, which is the only
    /// thing that explains the incident and never reaches the response body.
    /// </summary>
    private static UpstreamException RevocationNotRecorded(Exception cause) => new(
        ErrorCodes.UpstreamUnavailable,
        "The session was revoked, but the revocation could not be published to the token "
        + "revocation set. Already-issued access tokens for this session may remain usable until "
        + "they expire.",
        cause);
}
