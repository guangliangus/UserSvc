using System.ComponentModel.DataAnnotations;
using Shouldly;
using UserSvc.Application.Features.RiskControl;
using Xunit;

namespace UserSvc.UnitTests.RiskControl;

/// <summary>
/// Startup validation. Each rule here guards a misconfiguration whose only other symptom is a 500
/// from a public endpoint, which is a far more expensive place to find it.
/// </summary>
public sealed class RiskControlOptionsTests
{
    [Fact]
    public void TheDefaultsAreValid() => Validate(new RiskControlOptions()).ShouldBeEmpty();

    /// <summary>
    /// A threshold of 1 challenges the very first send anybody ever makes. That is not throttling,
    /// it is an outage with a CAPTCHA on it.
    /// </summary>
    [Fact]
    public void AThresholdOfOneIsRefused() =>
        Validate(new RiskControlOptions { SendCodeThreshold = 1 }).ShouldNotBeEmpty();

    /// <summary>
    /// The windows become rate-limit policy windows, and that type rejects a fractional second
    /// because the window is part of a Redis counter's identity. Caught here, the message names the
    /// configuration key; caught there, it is an ArgumentOutOfRangeException from inside a security
    /// control on the send path.
    /// </summary>
    [Theory]
    [InlineData(1500)]
    [InlineData(60_500)]
    public void AFractionalWindowIsRefused(int milliseconds) =>
        Validate(new RiskControlOptions { SendCodeWindow = TimeSpan.FromMilliseconds(milliseconds) })
            .ShouldNotBeEmpty();

    /// <summary>0 is the documented off switch and stays legal; 1 would cool a subject down on
    /// their first failed assessment, which nobody can tell apart from a broken CAPTCHA.</summary>
    [Fact]
    public void TheFailureEscalationIsEitherOffOrGivesTheUserASecondChance()
    {
        Validate(new RiskControlOptions { CaptchaFailThreshold = 0 }).ShouldBeEmpty();
        Validate(new RiskControlOptions { CaptchaFailThreshold = 1 }).ShouldNotBeEmpty();
        Validate(new RiskControlOptions { CaptchaFailThreshold = 2 }).ShouldBeEmpty();
    }

    [Fact]
    public void AnUnknownRegionIsRefused() =>
        Validate(new RiskControlOptions { AppRegion = "mars" }).ShouldNotBeEmpty();

    /// <summary>
    /// A configured region wins over the request's language, including "overseas": a deployment
    /// does not become a CN deployment because one caller asked in Chinese.
    /// </summary>
    [Theory]
    [InlineData("cn", "en-US", "cn")]
    [InlineData("overseas", "zh-CN", "overseas")]
    [InlineData("", "zh-CN", "cn")]
    [InlineData("", "en-US", "overseas")]
    [InlineData(null, null, "overseas")]
    public void TheRegionComesFromTheDeploymentFirstAndTheRequestSecond(
        string? appRegion,
        string? language,
        string expected) =>
        CaptchaRegions.Resolve(appRegion, language).ShouldBe(expected);

    /// <summary>An unrecognised platform gets the default provider key rather than a 400: the
    /// platform only selects a key, and a new client should still get a real assessment.</summary>
    [Theory]
    [InlineData("ios", "ios")]
    [InlineData(" Android ", "android")]
    [InlineData("windows-phone", "web")]
    [InlineData("", "web")]
    [InlineData(null, "web")]
    public void AnUnknownPlatformFallsBackToWeb(string? platform, string expected) =>
        CaptchaPlatforms.Normalize(platform).ShouldBe(expected);

    private static IReadOnlyList<ValidationResult> Validate(RiskControlOptions options)
    {
        var results = new List<ValidationResult>();

        Validator.TryValidateObject(options, new ValidationContext(options), results, validateAllProperties: true);

        return results;
    }
}
