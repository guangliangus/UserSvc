using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Infrastructure.Platform;

/// <summary>
/// The consume-once marker on Redis. Keys are <c>{prefix}consumed:{purpose}:{id}</c> and expire with
/// the credential they are about, so the key space is bounded by the last few minutes of sign-ins
/// and needs no cleanup job - the same property the revocation set and the rate-limit counters rely
/// on.
/// <para>
/// <b>One <c>SET NX PX</c>, and the atomicity is the whole mechanism.</b> <c>NX</c> makes the write
/// succeed only if the key is absent, and Redis executes it as one step, so of two redemptions of
/// one ticket arriving at two pods in the same millisecond exactly one gets <c>true</c>. The
/// <c>EXISTS</c>-then-<c>SET</c> pair that reads more naturally is precisely the wrong thing here:
/// both would find the key absent and both would be told they had claimed it, which is the replay
/// this class exists to stop, now only harder to reproduce.
/// </para>
/// <para>
/// <b>It fails CLOSED, unlike everything else this file sits beside.</b> The neighbouring rate
/// limiter allows on a Redis failure and the revocation store's read reports "not revoked"; this
/// one throws. See <see cref="ISingleUseMarkerStore"/> for the reasoning - in short, those two are
/// extra checks with something underneath them, and this one is the only thing that knows whether a
/// credential has been spent. Do not "make it consistent" with its neighbours: consistency here
/// means silently making an intercepted ticket replayable again for the duration of a Redis blip.
/// </para>
/// <para>
/// Exception handling covers the four shapes a StackExchange.Redis failure takes -
/// <c>RedisTimeoutException</c> derives from <see cref="TimeoutException"/>,
/// <c>RedisCommandException</c> straight from <see cref="Exception"/>, and a fresh multiplexer's
/// first command can surface <c>TaskCanceledException</c> - because here a missed one would escape
/// as a raw 500 <c>INTERNAL_ERROR</c> instead of the 502 that says which side is at fault.
/// </para>
/// </summary>
public sealed class RedisSingleUseMarkerStore(
    IConnectionMultiplexer connection,
    IOptions<RedisOptions> options,
    ILogger<RedisSingleUseMarkerStore> logger) : ISingleUseMarkerStore
{
    /// <summary>The value carries nothing: only the key's existence and its TTL mean anything. The
    /// same choice, for the same reason, as the revocation set's marker.</summary>
    private const string Marker = "1";

    /// <summary>
    /// Read at the point of use, never in a field initializer (docs/architecture.md: "a missing
    /// capability may only break itself"). <c>IOptions.Value</c> is where DataAnnotations
    /// validation runs, so binding it into a field makes merely <i>constructing</i> this store
    /// throw - and this store is a singleton on the dependency graph of the back-office sign-in
    /// service, which the token endpoint builds, so a bad <c>Redis</c> section would surface as
    /// "back-office sign-in is broken" rather than as "Redis is misconfigured". <c>.Value</c> is
    /// cached, so reading it per call costs nothing.
    /// </summary>
    private string KeyPrefix => options.Value.KeyPrefix;

    public async Task<bool> TryClaimAsync(
        string purpose,
        string id,
        TimeSpan timeToLive,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        if (timeToLive <= TimeSpan.Zero)
        {
            // A non-positive expiry makes Redis reject the SET outright, and the caller would read
            // that as "the store is unreachable" and answer 502 for what is a bad argument. Worse,
            // a caller that passed zero believing it meant "no expiry" would be writing an
            // immortal key per sign-in into a store nothing ever prunes.
            throw new ArgumentOutOfRangeException(
                nameof(timeToLive),
                timeToLive,
                "A single-use marker must outlive the credential it is about, so its time to live "
                + "has to be positive.");
        }

        // No StackExchange.Redis async method accepts a CancellationToken, so the token is honoured
        // at the boundary only. The command itself, once issued, is not cancellable.
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            // Named arguments on purpose: the positional five-argument form binds to a hidden
            // legacy overload with a different meaning for the trailing parameters - the same trap
            // the revocation store's comment records.
            return await connection.GetDatabase().StringSetAsync(
                KeyFor(purpose, id),
                Marker,
                expiry: timeToLive,
                keepTtl: false,
                when: When.NotExists,
                flags: CommandFlags.None);
        }
        catch (Exception ex) when (IsStoreFailure(ex, cancellationToken))
        {
            throw CannotTell(purpose, ex);
        }
    }

    private string KeyFor(string purpose, string id) => $"{KeyPrefix}consumed:{purpose}:{id}";

    private static bool IsStoreFailure(Exception exception, CancellationToken cancellationToken) =>
        exception switch
        {
            RedisException or RedisTimeoutException or RedisCommandException => true,
            OperationCanceledException => !cancellationToken.IsCancellationRequested,
            _ => false,
        };

    /// <summary>
    /// 502, not 500 and not 401: the caller did nothing wrong, and this is not evidence that their
    /// credential was replayed. Answering "invalid credential" would be the comfortable lie - it
    /// would send an operator hunting for a stolen ticket during what is actually a Redis outage.
    /// The Redis failure type travels in the inner exception, which reaches the log and never the
    /// response body.
    /// </summary>
    private UpstreamException CannotTell(string purpose, Exception cause)
    {
        logger.LogError(
            cause,
            "Could not claim the single-use marker for {Purpose}, so it cannot be established "
            + "whether this credential has already been redeemed. Refusing it - a replay must not "
            + "be allowed through on the strength of a Redis failure.",
            purpose);

        return new UpstreamException(
            ErrorCodes.UpstreamUnavailable,
            "This credential could not be verified as unused. Sign in again.",
            cause);
    }
}
