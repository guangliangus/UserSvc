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
    /// <summary>Every call, as <c>dimension|subject</c>, so a test can assert that a dimension was
    /// never counted at all.</summary>
    public List<string> Calls { get; } = [];

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
}
