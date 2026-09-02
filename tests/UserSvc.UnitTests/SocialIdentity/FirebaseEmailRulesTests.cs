using Shouldly;
using UserSvc.Application.Features.SocialIdentity;
using Xunit;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// Which addresses out of a Firebase sign-in count as an address the person actually owns.
/// </summary>
public sealed class FirebaseEmailRulesTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("   ", "")]
    [InlineData("  carol@gmail.com  ", "carol@gmail.com")]
    public void AnAddressIsTrimmedAndBlanksAreAbsent(string? input, string expected)
    {
        FirebaseEmailRules.UsableEmail(input).ShouldBe(expected);
    }

    /// <summary>
    /// A relay address is unique to this app: it can never match another account, and the user can
    /// never sign in elsewhere with it. Reporting it as absent is what stops it becoming a login
    /// identifier nobody can type.
    /// </summary>
    [Theory]
    [InlineData("abc123@privaterelay.appleid.com")]
    [InlineData("ABC123@PRIVATERELAY.APPLEID.COM")]
    [InlineData("  abc@PrivateRelay.AppleID.com  ")]
    public void AnApplePrivateRelayAddressIsReportedAsAbsent(string input)
    {
        FirebaseEmailRules.UsableEmail(input).ShouldBeEmpty();
        FirebaseEmailRules.IsAppleProxyEmail(input).ShouldBeTrue();
    }

    /// <summary>Apple's real address domain is not the relay domain, and a lookalike is not either.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("carol@gmail.com")]
    [InlineData("carol@appleid.com")]
    [InlineData("carol@privaterelay.appleid.com.example.com")]
    public void EverythingElseIsARealAddress(string? input)
    {
        FirebaseEmailRules.IsAppleProxyEmail(input).ShouldBeFalse();
    }
}
