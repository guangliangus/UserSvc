using Shouldly;
using UserSvc.Application.Ports.External;
using Xunit;

namespace UserSvc.UnitTests.External;

/// <summary>
/// The decision is built through factories so that no caller can produce a combination that means
/// nothing - a cooldown with no reset time, or an Allow that carries a wait.
/// </summary>
public sealed class SendCodeRiskDecisionTests
{
    [Fact]
    public void AllowCarriesNoDeadline()
    {
        var decision = SendCodeRiskDecision.Allow();

        decision.Action.ShouldBe(SendCodeRiskDecision.RiskAction.Allow);
        decision.ResetAt.ShouldBeNull();
        decision.RetryAfter.ShouldBe(TimeSpan.Zero);
    }

    /// <summary>
    /// CaptchaRequired is an invitation to retry immediately with proof, not a wait - a Retry-After
    /// on it would tell the client to sit still while holding a token that expires.
    /// </summary>
    [Fact]
    public void CaptchaRequiredCarriesNoWait()
    {
        var decision = SendCodeRiskDecision.CaptchaRequired();

        decision.Action.ShouldBe(SendCodeRiskDecision.RiskAction.CaptchaRequired);
        decision.RetryAfter.ShouldBe(TimeSpan.Zero);
    }

    [Fact]
    public void CooldownCarriesBothTheInstantAndTheWait()
    {
        var resetAt = new DateTimeOffset(2026, 9, 1, 12, 5, 0, TimeSpan.Zero);

        var decision = SendCodeRiskDecision.Cooldown(resetAt, TimeSpan.FromMinutes(5));

        decision.Action.ShouldBe(SendCodeRiskDecision.RiskAction.Cooldown);
        decision.ResetAt.ShouldBe(resetAt);
        decision.RetryAfter.ShouldBe(TimeSpan.FromMinutes(5));
    }

    /// <summary>
    /// A cooldown read a moment after it lapsed produces a negative remainder. Passing that through
    /// would put a negative Retry-After on the wire, which clients treat in whatever way they like.
    /// </summary>
    [Fact]
    public void AlreadyLapsedCooldownsClampToZeroRatherThanGoingNegative()
    {
        SendCodeRiskDecision.Cooldown(DateTimeOffset.UnixEpoch, TimeSpan.FromSeconds(-3))
            .RetryAfter.ShouldBe(TimeSpan.Zero);
    }
}
