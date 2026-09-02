using Shouldly;
using UserSvc.Application.Ports.Platform;
using Xunit;

namespace UserSvc.UnitTests.Platform;

/// <summary>
/// <see cref="RateLimitDecision.From"/> is the port's arithmetic contract: it decides what "5 per
/// minute" means and what the client is told to wait. Both are off-by-one traps, so both are
/// pinned here rather than left to the adapter.
/// </summary>
public sealed class RateLimitDecisionTests
{
    private static readonly RateLimitPolicy FivePerMinute = RateLimitPolicy.PerMinute(5);

    [Fact]
    public void TheFirstRequestIsAllowedAndSpendsOneUnitOfBudget()
    {
        var decision = RateLimitDecision.From(1, FivePerMinute, TimeSpan.FromSeconds(60));

        decision.Allowed.ShouldBeTrue();
        decision.Remaining.ShouldBe(4);
        decision.RetryAfter.ShouldBe(TimeSpan.Zero);
    }

    /// <summary>"5 per minute" serves five requests. Refusing the fifth would make it mean four.</summary>
    [Fact]
    public void TheRequestThatReachesTheLimitIsStillServed()
    {
        var decision = RateLimitDecision.From(5, FivePerMinute, TimeSpan.FromSeconds(30));

        decision.Allowed.ShouldBeTrue();
        decision.Remaining.ShouldBe(0);
        decision.RetryAfter.ShouldBe(TimeSpan.Zero);
    }

    [Fact]
    public void TheRequestPastTheLimitIsRefusedAndToldWhenToComeBack()
    {
        var decision = RateLimitDecision.From(6, FivePerMinute, TimeSpan.FromSeconds(30));

        decision.Allowed.ShouldBeFalse();
        decision.Remaining.ShouldBe(0);
        decision.RetryAfter.ShouldBe(TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// The wait is what is left of the window, not the window itself - a caller 55 seconds in gets
    /// 5 seconds. Rounding it up to a full minute would waste the client's next attempt.
    /// </summary>
    [Fact]
    public void TheWaitComesFromTheStoresRemainingTimeNotTheWindowLength()
    {
        RateLimitDecision.From(9, FivePerMinute, TimeSpan.FromSeconds(5))
            .RetryAfter.ShouldBe(TimeSpan.FromSeconds(5));
    }

    /// <summary>
    /// A counter with no readable deadline (expired between the increment and the read, or never
    /// given a TTL) falls back to the full window: an over-estimate the client can act on beats a
    /// zero that sends it straight back.
    /// </summary>
    [Fact]
    public void AMissingDeadlineFallsBackToTheFullWindow()
    {
        RateLimitDecision.From(6, FivePerMinute, TimeSpan.Zero)
            .RetryAfter.ShouldBe(TimeSpan.FromMinutes(1));
    }

    [Fact]
    public void RemainingNeverGoesNegativeHoweverFarOverTheLimit()
    {
        RateLimitDecision.From(5_000, FivePerMinute, TimeSpan.FromSeconds(1)).Remaining.ShouldBe(0);
    }

    /// <summary>
    /// The degraded decision reports the full budget on purpose: nothing was counted, so nothing
    /// was spent, and inventing a decrement would put a number in the response header that no
    /// counter ever produced.
    /// </summary>
    [Fact]
    public void FailingOpenAllowsAndClaimsNoKnowledgeOfSpentBudget()
    {
        var decision = RateLimitDecision.FailOpen(FivePerMinute);

        decision.Allowed.ShouldBeTrue();
        decision.Remaining.ShouldBe(5);
        decision.RetryAfter.ShouldBe(TimeSpan.Zero);
    }
}
