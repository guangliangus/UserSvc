using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Infrastructure.Platform;

/// <summary>
/// Fixed-window counting on Redis. Keys are
/// <c>{prefix}ratelimit:{dimension}:{windowSeconds}s:{sha256(subject)}</c> and expire with the
/// window, so the key space is bounded by the traffic of the last window and needs no cleanup job -
/// the same property the revocation set relies on.
/// <para>
/// <b>Failure is open, in the same direction as the revocation set's read path and the opposite of
/// its write path</b> (see the failure-semantics table in docs/architecture.md). The test there is
/// "what does it fall back to". A lost revocation write leaves a signed-out device working with no
/// other backstop, so it throws. A lost increment merely lets one more request through a limit that
/// exists to shave load off endpoints which are still authenticated, validated and audited -
/// whereas refusing every request during a Redis blip would take down login, sign-up and
/// verification codes at once. The limiter would then cause precisely the outage it was installed
/// to prevent.
/// </para>
/// <para>
/// The accepted cost is worth naming: while Redis is unreachable the service is unthrottled, and
/// brute force is bounded only by whatever else stands in front of it. That is why every degraded
/// call logs a warning - the rate of those lines is the only signal that the window is open.
/// </para>
/// <para>
/// Exception handling follows <see cref="RedisSessionRevocationStore"/>, and for the same
/// non-obvious reason: <c>RedisTimeoutException</c> derives from <see cref="TimeoutException"/> and
/// <c>RedisCommandException</c> derives straight from <see cref="Exception"/>, so catching
/// <c>RedisException</c> alone would miss every timeout - which is the failure fail-open exists
/// for.
/// </para>
/// </summary>
public sealed class RedisRateLimiter(
    IConnectionMultiplexer connection,
    IOptions<RedisOptions> options,
    ILogger<RedisRateLimiter> logger) : IRateLimiter
{
    /// <summary>
    /// One round trip, one atomic step, and the TTL is set <b>only when the key has no deadline</b>.
    /// <para>
    /// The plain INCR-then-EXPIRE pair was rejected for a specific failure: if the connection drops
    /// between the two commands, the key survives with no TTL at all and the subject is locked out
    /// permanently, because nothing will ever reset a counter that cannot expire. A Lua script runs
    /// both under one Redis execution and cannot be interrupted halfway. The risk taken in exchange
    /// is the one every script takes - the body must stay small and free of anything blocking,
    /// since it holds the whole server for its duration - and three commands on one key is about as
    /// small as it gets.
    /// </para>
    /// <para>
    /// The condition is <c>PTTL &lt; 0</c> rather than <c>count == 1</c>, and the difference is the
    /// whole point of the paragraph above. A fresh key answers -1, so both spellings arm the new
    /// counter; only this one also re-arms a counter that somehow already exists without an expiry -
    /// restored from an RDB written by an older build, set by hand during an incident, left behind
    /// by any future edit to this script. Under <c>count == 1</c> such a key is immortal and its
    /// subject is refused forever, which is exactly the outcome the script was chosen to prevent.
    /// The steady-state cost is nil: the PTTL is read either way, because the reply carries it.
    /// </para>
    /// <para>
    /// Not refreshing the TTL on every increment is what makes this a fixed window. Refreshing it -
    /// which is what the Go service did - means a client that keeps retrying keeps pushing its own
    /// reset time away, so a one-minute limit becomes an indefinite lockout for exactly the caller
    /// that is politely retrying. It also makes the Retry-After we hand back a lie, since the
    /// deadline moves every time the client obeys it.
    /// </para>
    /// </summary>
    private const string IncrementInWindowScript =
        """
        local count = redis.call('INCR', KEYS[1])
        local pttl = redis.call('PTTL', KEYS[1])
        if pttl < 0 then
          redis.call('PEXPIRE', KEYS[1], ARGV[1])
          pttl = tonumber(ARGV[1])
        end
        return { count, pttl }
        """;

    private readonly string _keyPrefix = options.Value.KeyPrefix;

    public async Task<RateLimitDecision> TryAcquireAsync(
        string dimension,
        string key,
        RateLimitPolicy policy,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dimension);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(policy);

        // No StackExchange.Redis async method accepts a CancellationToken, so the token is honoured
        // at the boundary only. The command itself, once issued, is not cancellable.
        cancellationToken.ThrowIfCancellationRequested();

        var redisKey = BuildKey(_keyPrefix, dimension, key, policy.Window);

        try
        {
            var reply = await connection.GetDatabase().ScriptEvaluateAsync(
                IncrementInWindowScript,
                [redisKey],
                [(long)policy.Window.TotalMilliseconds]);

            return Interpret(reply, dimension, policy);
        }
        catch (RedisException ex)
        {
            return FailOpen(dimension, policy, ex);
        }
        catch (RedisTimeoutException ex)
        {
            return FailOpen(dimension, policy, ex);
        }
        catch (RedisCommandException ex)
        {
            return FailOpen(dimension, policy, ex);
        }
    }

    /// <summary>
    /// Builds the counter's key. Public because the layout is a deployment fact - operators grep
    /// for these - and because it is the one part of this adapter that is worth testing without a
    /// Redis to talk to.
    /// <para>
    /// Layout: <c>{prefix}ratelimit:{dimension}:{windowSeconds}s:{sha256hex(subject)}</c>.
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <b>The prefix comes from <see cref="RedisOptions.KeyPrefix"/></b>, the same one the
    /// revocation set uses, so several services can share one Redis without colliding. Key
    /// prefixing is the only isolation available - Redis Cluster exposes db 0 and nothing else.
    /// </item>
    /// <item>
    /// <b>The window is part of the identity.</b> A per-minute and a per-hour limit on the same
    /// subject are two counters; sharing one would let whichever TTL was written last decide when
    /// both reset.
    /// </item>
    /// <item>
    /// <b>The subject is hashed</b>, which fixes its length and shape so no separator inside it can
    /// forge a different key, and keeps raw phone numbers, emails and IP addresses out of anything
    /// that dumps the key space. It is not a privacy control - the phone number space is small
    /// enough to enumerate against a plain digest - just a way to stop identifiers travelling
    /// further than they need to.
    /// </item>
    /// </list>
    /// <para>
    /// With a fixed-length digest at the end and a digits-then-'s' window token before it, the only
    /// way two different subjects could produce one key is a ':' inside the dimension, which is
    /// rejected below. That makes the mapping injective, which is the whole point: a collision here
    /// silently merges two budgets.
    /// </para>
    /// </summary>
    public static string BuildKey(string keyPrefix, string dimension, string key, TimeSpan window)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dimension);

        if (dimension.Contains(':', StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "A rate-limit dimension must not contain ':' - it is the key separator, and a "
                + "dimension carrying one could be spelled two ways and share a counter with an "
                + "unrelated limit.",
                nameof(dimension));
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{keyPrefix}ratelimit:{dimension}:{(long)window.TotalSeconds}s:{HashSubject(key)}");
    }

    /// <summary>
    /// Normalizes before hashing, so <c>" User@Example.com "</c> and <c>"user@example.com"</c> are
    /// one subject. Without it a limit is bypassed by adding a space.
    /// </summary>
    private static string HashSubject(string key) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key.Trim().ToLowerInvariant())));

    /// <summary>
    /// Reads the script's <c>{count, pttl}</c> reply.
    /// <para>
    /// The parsing sits inside a <see cref="InvalidCastException"/> guard because the conversions
    /// here <b>throw</b> on an unexpected shape rather than returning null - a single-value reply
    /// makes <c>(RedisResult[])</c> itself throw. Without the guard, a reply this file did not
    /// expect would leave as a 500 from whatever endpoint the limiter was protecting, which is the
    /// one outcome the whole fail-open design exists to avoid.
    /// </para>
    /// </summary>
    private RateLimitDecision Interpret(RedisResult reply, string dimension, RateLimitPolicy policy)
    {
        try
        {
            if ((RedisResult[]?)reply is { Length: 2 } parts)
            {
                var count = (long)parts[0];
                var timeToLiveMilliseconds = (long)parts[1];

                // The script normalizes PTTL's -1 (no expiry) into the window it just set, so a
                // non-positive value reaching here means the key vanished between the INCR and the
                // read (-2) - still no usable deadline, which From() turns into the full window.
                var timeToLive = timeToLiveMilliseconds > 0
                    ? TimeSpan.FromMilliseconds(timeToLiveMilliseconds)
                    : TimeSpan.Zero;

                return RateLimitDecision.From(count, policy, timeToLive);
            }
        }
        catch (InvalidCastException ex)
        {
            return UnexpectedReply(dimension, policy, ex);
        }

        return UnexpectedReply(dimension, policy, null);
    }

    /// <summary>
    /// Only reachable if the script stops returning a two-integer array, which is a defect in this
    /// file rather than a Redis fault. It still fails open - a limiter that 500s the endpoint it
    /// guards is worse than one that lets traffic through - but at Error, because unlike an outage
    /// this will not fix itself.
    /// </summary>
    private RateLimitDecision UnexpectedReply(string dimension, RateLimitPolicy policy, Exception? cause)
    {
        logger.LogError(
            cause,
            "Rate-limit script for dimension {Dimension} returned an unexpected reply shape; "
            + "failing open and not counting this request.",
            dimension);

        return RateLimitDecision.FailOpen(policy);
    }

    private RateLimitDecision FailOpen(string dimension, RateLimitPolicy policy, Exception cause)
    {
        // Warning, not Error: this request is still being served correctly. One line per affected
        // request is the point - the rate is what tells an operator how much traffic is currently
        // unthrottled, which a single line at the moment the connection dropped could not.
        logger.LogWarning(
            cause,
            "Redis rate-limit counter failed for dimension {Dimension}; failing open and allowing "
            + "the request. The {Limit}-per-{Window} limit is not being enforced while this lasts.",
            dimension,
            policy.Limit,
            policy.Window);

        return RateLimitDecision.FailOpen(policy);
    }
}
