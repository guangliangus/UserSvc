using System.Globalization;
using UserSvc.Application.Ports.Platform;
using UserSvc.Infrastructure.Platform;

namespace UserSvc.UnitTests.RiskControl;

/// <summary>
/// A fixed-window limiter that counts into <see cref="FakeRedis"/> under the <b>real</b> adapter's
/// key layout.
/// <para>
/// Using <see cref="RedisRateLimiter.BuildKey"/> here rather than an invented key is the point of
/// the double: clearing a subject's counters after a redeemed CAPTCHA works by deleting exactly
/// those keys, so a test that counted somewhere else would pass while the production path quietly
/// cleared nothing.
/// </para>
/// </summary>
internal sealed class FakeRateLimiter(FakeRedis redis, string keyPrefix) : IRateLimiter
{
    /// <summary>Every counting call, as <c>dimension|subject</c>, so a test can assert that a
    /// dimension was never counted at all.</summary>
    public List<string> Calls { get; } = [];

    /// <summary>Every read-only check, kept apart from <see cref="Calls"/> because the whole point
    /// of the distinction is that one spends budget and the other does not.</summary>
    public List<string> Peeks { get; } = [];

    /// <summary>Every clear.</summary>
    public List<string> Resets { get; } = [];

    /// <summary>Answer as the real adapter does when Redis is unreachable: allow, count nothing.</summary>
    public bool FailOpen { get; set; }

    public Task<RateLimitDecision> TryAcquireAsync(
        string dimension,
        string key,
        RateLimitPolicy policy,
        CancellationToken cancellationToken)
    {
        Calls.Add($"{dimension}|{key}");

        if (FailOpen)
        {
            return Task.FromResult(RateLimitDecision.FailOpen(policy));
        }

        var count = redis.Increment(
            RedisRateLimiter.BuildKey(keyPrefix, dimension, key, policy.Window),
            policy.Window);

        return Task.FromResult(RateLimitDecision.From(count, policy, policy.Window));
    }

    /// <summary>Reads the counter without moving it, from the same key the real adapter counts
    /// into - so a caller that peeks one key layout and counts another shows up here.</summary>
    public Task<RateLimitDecision> PeekAsync(
        string dimension,
        string key,
        RateLimitPolicy policy,
        CancellationToken cancellationToken)
    {
        Peeks.Add($"{dimension}|{key}");

        if (FailOpen)
        {
            return Task.FromResult(RateLimitDecision.FailOpen(policy));
        }

        var stored = redis.Peek(RedisRateLimiter.BuildKey(keyPrefix, dimension, key, policy.Window));
        var count = stored is null ? 0 : long.Parse(stored, CultureInfo.InvariantCulture);

        return Task.FromResult(RateLimitDecision.Peek(count, policy, policy.Window));
    }

    /// <summary>Deletes through <see cref="FakeRedis"/>'s own database, so a reset that computed
    /// the wrong keys leaves the counters standing here exactly as it would in production.</summary>
    public async Task ResetAsync(
        string dimension,
        string key,
        IReadOnlyList<RateLimitPolicy> policies,
        CancellationToken cancellationToken)
    {
        Resets.Add($"{dimension}|{key}");

        if (FailOpen)
        {
            return;
        }

        foreach (var policy in policies)
        {
            await redis.Database.KeyDeleteAsync(
                RedisRateLimiter.BuildKey(keyPrefix, dimension, key, policy.Window));
        }
    }
}
