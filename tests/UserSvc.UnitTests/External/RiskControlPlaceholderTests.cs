using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.External;
using UserSvc.Infrastructure.External;
using Xunit;

namespace UserSvc.UnitTests.External;

/// <summary>
/// The placeholder's answers are the point of these tests. "It is only a stand-in" is exactly the
/// argument that would let it start approving CAPTCHAs, so each of the three answers is pinned
/// here with the reason it is the safe one.
/// </summary>
public sealed class RiskControlPlaceholderTests
{
    private static readonly SendCodeRiskContext Context = new("user@example.com", "email", "device-1");

    private static PlaceholderRiskControlService Sut =>
        new(NullLogger<PlaceholderRiskControlService>.Instance);

    /// <summary>
    /// Throttling is the one decision here that is safe to answer "allow" to - the port already
    /// promises a counting failure degrades that way, and the per-IP limiter is the backstop.
    /// Answering CaptchaRequired would be worse than useless: nothing can issue a token to redeem,
    /// so send-code would be dead rather than unthrottled.
    /// </summary>
    [Fact]
    public async Task SendCodeThrottlingAllows()
    {
        var decision = await Sut.EvaluateSendCodeAsync(Context, CancellationToken.None);

        decision.Action.ShouldBe(SendCodeRiskDecision.RiskAction.Allow);
        decision.RetryAfter.ShouldBe(TimeSpan.Zero);
        decision.ResetAt.ShouldBeNull();
    }

    /// <summary>
    /// Honouring a token no provider ever assessed would turn the CAPTCHA bypass into a header
    /// anyone can send. Any token, well-formed or not, is refused.
    /// </summary>
    [Theory]
    [InlineData("cpt_anything")]
    [InlineData("")]
    [InlineData("   ")]
    public async Task NoCaptchaTokenIsEverRedeemed(string token) =>
        (await Sut.TryConsumeCaptchaTokenAsync(token, Context, CancellationToken.None)).ShouldBeFalse();

    /// <summary>
    /// The method that could actually mint a bypass credential refuses loudly instead. A silent
    /// "pass" here would remove the CAPTCHA gate while every response still claimed it had been
    /// cleared - a failure that looks exactly like success.
    /// </summary>
    [Fact]
    public async Task VerifyingACaptchaFailsLoudlyRatherThanIssuingAToken()
    {
        var context = new CaptchaVerificationContext(
            "provider-token",
            "user@example.com",
            "email",
            "device-1",
            "overseas",
            "web",
            "203.0.113.7",
            "curl/8.4.0");

        var ex = await Should.ThrowAsync<AppException>(
            () => Sut.VerifyCaptchaAsync(context, CancellationToken.None));

        // 500, not 502: nothing upstream failed, because nothing upstream was asked.
        ex.StatusCode.ShouldBe(500);
        ex.ErrorCode.ShouldBe(ErrorCodes.InternalError);
    }
}
