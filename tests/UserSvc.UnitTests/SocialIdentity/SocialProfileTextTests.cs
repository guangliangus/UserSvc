using Shouldly;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Domain.Users;
using Xunit;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>Naming an account nobody named, and how much of an identifier may leave the service.</summary>
public sealed class SocialProfileTextTests
{
    /// <summary>
    /// A name the person chose beats a string scraped out of their address, and both beat a generic
    /// label. Kept identical to the sign-up form's default so an account created by signing in with
    /// WeChat is indistinguishable from one registered by hand.
    /// </summary>
    [Theory]
    [InlineData("Dana", "dana@example.com", "Dana")]
    [InlineData("  Dana  ", "dana@example.com", "Dana")]
    [InlineData("", "dana@example.com", "dana")]
    [InlineData(null, "dana@example.com", "dana")]
    [InlineData("   ", "  dana@example.com ", "dana")]
    public void ANameBeatsAnAddressWhichBeatsTheDefault(string? name, string? email, string expected)
    {
        SocialProfileText.Nickname(name, email).ShouldBe(expected);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", "")]
    [InlineData(null, "not-an-address")]
    [InlineData(null, "@leading-at.example.com")]
    public void NothingToDeriveFromFallsBackToTheDefault(string? name, string? email)
    {
        SocialProfileText.Nickname(name, email).ShouldBe(SocialProfileText.DefaultNickname);
    }

    [Theory]
    [InlineData("carol@gmail.com", "car***@gmail.com")]
    [InlineData("ab@gmail.com", "ab***@gmail.com")]
    [InlineData("a@b.com", "a***@b.com")]
    public void AnAddressKeepsItsDomainAndThreeCharactersOfTheLocalPart(string input, string expected)
    {
        SocialProfileText.Mask(IdentityTypes.Email, input).ShouldBe(expected);
    }

    /// <summary>The informative end of a phone number is the last few digits.</summary>
    [Theory]
    [InlineData("+8613900000000", "+86****0000")]
    [InlineData("13900000000", "139****0000")]
    [InlineData("1234567", "****4567")]
    [InlineData("123", "***")]
    public void APhoneNumberKeepsItsPrefixAndItsLastFourDigits(string input, string expected)
    {
        SocialProfileText.Mask(IdentityTypes.Phone, input).ShouldBe(expected);
    }

    /// <summary>
    /// A provider subject has no informative end, so it is masked from the left and only its tail
    /// survives - enough for a support engineer to match against a log line, not enough to be one.
    /// </summary>
    [Fact]
    public void AProviderSubjectIsMaskedFromTheLeft()
    {
        var masked = SocialProfileText.Mask(IdentityTypes.Wechat, "wx-open-abcdef123456");

        masked.ShouldBe("****3456");
        masked.ShouldNotContain("wx-open");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void NothingMasksToNothing(string? input)
    {
        SocialProfileText.Mask(IdentityTypes.Email, input).ShouldBeEmpty();
    }
}
