using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.RiskControl;
using UserSvc.Application.Ports.External;
using Xunit;

namespace UserSvc.UnitTests.RiskControl;

/// <summary>
/// The mapping layer over <see cref="IRiskControlService"/>. There is little logic here by design,
/// so what these tests pin is the little there is: what the port is told about the request, and
/// which malformed payloads never reach it.
/// </summary>
public sealed class CaptchaAppServiceTests
{
    private static readonly CaptchaRequestContext Context =
        new("device-1", " iOS ", "zh-CN", "203.0.113.7", "curl/8.4.0");

    private readonly IRiskControlService _riskControl = Substitute.For<IRiskControlService>();

    private CaptchaAppService Build(string appRegion = CaptchaRegions.Overseas)
    {
        _riskControl
            .VerifyCaptchaAsync(Arg.Any<CaptchaVerificationContext>(), Arg.Any<CancellationToken>())
            .Returns(new CaptchaVerificationResult("cpt_token", TimeSpan.FromMinutes(2)));

        return new CaptchaAppService(_riskControl, Options.Create(new RiskControlOptions { AppRegion = appRegion }));
    }

    [Fact]
    public async Task TheTokenAndItsLifetimeAreReturnedToTheClient()
    {
        var response = await Build().VerifyAsync(Valid(), Context, CancellationToken.None);

        response.CaptchaToken.ShouldBe("cpt_token");

        // Seconds, because the client counts down with it - not an instant.
        response.ExpiresIn.ShouldBe(120);
    }

    /// <summary>
    /// The platform is normalized before the port sees it, and the region is resolved from the
    /// deployment rather than from the caller's language when the deployment has said which it is.
    /// </summary>
    [Fact]
    public async Task TheRequestFactsReachThePortNormalized()
    {
        await Build().VerifyAsync(Valid(), Context, CancellationToken.None);

        await _riskControl.Received(1).VerifyCaptchaAsync(
            Arg.Is<CaptchaVerificationContext>(context =>
                context.Platform == "ios"
                && context.Region == CaptchaRegions.Overseas
                && context.DeviceId == "device-1"
                && context.ClientIpAddress == "203.0.113.7"
                && context.UserAgent == "curl/8.4.0"),
            Arg.Any<CancellationToken>());
    }

    /// <summary>An absent header is "unknown", not a signal that the caller has a blank user
    /// agent, so it reaches the provider as null.</summary>
    [Fact]
    public async Task AbsentNetworkFactsReachThePortAsUnknown()
    {
        await Build().VerifyAsync(Valid(), new CaptchaRequestContext("", "", "", "", "   "), CancellationToken.None);

        await _riskControl.Received(1).VerifyCaptchaAsync(
            Arg.Is<CaptchaVerificationContext>(context =>
                context.ClientIpAddress == null && context.UserAgent == null),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A blank target would bind every caller's token to one shared subject, and an unknown target
    /// type means the two endpoints are not talking about the same thing. Both are refused before
    /// anything is spent on a provider call.
    /// </summary>
    [Theory]
    [InlineData("", "user@example.com", "email")]
    [InlineData("answer", "", "email")]
    [InlineData("answer", "user@example.com", "")]
    [InlineData("answer", "user@example.com", "postcard")]
    public async Task AMalformedPayloadNeverReachesTheProvider(string answer, string target, string targetType)
    {
        var service = Build();
        var request = new CaptchaVerifyRequest { Answer = answer, Target = target, TargetType = targetType };

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => service.VerifyAsync(request, Context, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);

        await _riskControl.DidNotReceiveWithAnyArgs()
            .VerifyCaptchaAsync(default!, default);
    }

    /// <summary>
    /// The target's format is deliberately not checked here. The send path validates it, so a token
    /// bound to a malformed target is bound to a string that path rejects before it ever redeems -
    /// the check would refuse a request that is already harmless.
    /// </summary>
    [Fact]
    public async Task TheTargetFormatIsTheSendPathsBusinessAndNotCheckedHere()
    {
        var request = new CaptchaVerifyRequest { Answer = "answer", Target = "not-an-email", TargetType = "email" };

        await Should.NotThrowAsync(() => Build().VerifyAsync(request, Context, CancellationToken.None));
    }

    /// <summary>
    /// The endpoint is anonymous and both fields are attacker-supplied; the answer is also
    /// forwarded upstream. Without a ceiling, one request can make this service URL-encode and POST
    /// megabytes to the provider - amplification we pay for in both directions - so the size is
    /// refused here, before anything is spent.
    /// </summary>
    [Theory]
    [InlineData(8193, 10)]
    [InlineData(10, 321)]
    public async Task AnOversizedFieldNeverReachesTheProvider(int answerLength, int targetLength)
    {
        var service = Build();

        var request = new CaptchaVerifyRequest
        {
            Answer = new string('a', answerLength),
            Target = new string('t', targetLength),
            TargetType = "email",
        };

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => service.VerifyAsync(request, Context, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);

        // 400 rather than 413: 413 is the request entity being too large for the endpoint, which is
        // Kestrel's limit and Kestrel's answer. This is a normal-sized request with a nonsense
        // field in it.
        ex.StatusCode.ShouldBe(400);

        await _riskControl.DidNotReceiveWithAnyArgs().VerifyCaptchaAsync(default!, default);
    }

    /// <summary>The largest values that are still legal do reach the port - the caps are a ceiling
    /// on abuse, not a bound that clips a real provider token.</summary>
    [Fact]
    public async Task TheLargestLegalFieldsStillReachThePort()
    {
        var service = Build();

        var request = new CaptchaVerifyRequest
        {
            Answer = new string('a', 8192),
            Target = new string('t', 320),
            TargetType = "email",
        };

        await Should.NotThrowAsync(() => service.VerifyAsync(request, Context, CancellationToken.None));

        await _riskControl.ReceivedWithAnyArgs(1).VerifyCaptchaAsync(default!, default);
    }

    private static CaptchaVerifyRequest Valid() =>
        new() { Answer = " client-token ", Target = "user@example.com", TargetType = "email" };
}
