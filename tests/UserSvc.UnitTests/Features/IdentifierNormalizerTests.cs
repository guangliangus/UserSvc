using Shouldly;
using UserSvc.Application.Features.Registration;
using UserSvc.Domain.Users;
using Xunit;

namespace UserSvc.UnitTests.Features;

/// <summary>
/// Normalization decides what the blind index hashes, so every one of these cases is really a
/// statement about whether two spellings of one identifier can end up as two accounts.
/// </summary>
public sealed class IdentifierNormalizerTests
{
    [Theory]
    [InlineData("  Alice@Example.COM ", "alice@example.com")]
    [InlineData("alice@example.com", "alice@example.com")]
    [InlineData("ALICE+tag@Example.com", "alice+tag@example.com")]
    public void EmailAddressesAreLowercasedWhole(string input, string expected) =>
        IdentifierNormalizer.Normalize(IdentityTypes.Email, input).ShouldBe(expected);

    [Theory]
    [InlineData(" +886 912-345-678 ", "886912345678")]
    [InlineData("+886(912)345678", "886912345678")]
    [InlineData("+886912345678", "886912345678")]
    [InlineData("886912345678", "886912345678")]
    public void PhoneNumbersKeepTheirDigitsAndNothingElse(string input, string expected) =>
        IdentifierNormalizer.Normalize(IdentityTypes.Phone, input).ShouldBe(expected);

    /// <summary>
    /// The validator accepts a number with or without the leading plus, exactly as the send-code
    /// endpoint does. If normalization kept it, one telephone typed both ways would be two blind
    /// indexes, which the partial unique index would happily let become two accounts.
    /// </summary>
    [Fact]
    public void ThePlusIsNotPartOfAPhoneNumbersIdentity() =>
        IdentifierNormalizer.Normalize(IdentityTypes.Phone, "+886912345678")
            .ShouldBe(IdentifierNormalizer.Normalize(IdentityTypes.Phone, "886912345678"));

    /// <summary>
    /// Why the rule is "keep the digits" and not "drop this list of punctuation": a non-breaking
    /// space, pasted from a contact card, is invisible in every log and every bug report, and a
    /// blocklist that has not heard of it yields a second spelling of the same number.
    /// </summary>
    [Fact]
    public void InvisibleCharactersDoNotBecomeASecondSpellingOfTheSameNumber() =>
        IdentifierNormalizer.Normalize(IdentityTypes.Phone, "+886\u00a0912345678")
            .ShouldBe("886912345678");

    /// <summary>Clients still send the Go service's lowercase spelling.</summary>
    [Theory]
    [InlineData("email", IdentityTypes.Email)]
    [InlineData("EMAIL", IdentityTypes.Email)]
    [InlineData("Phone", IdentityTypes.Phone)]
    public void TheWireSpellingOfAnIdentityTypeIsMatchedCaseInsensitively(string input, string expected) =>
        IdentifierNormalizer.ResolveIdentityType(input).ShouldBe(expected);

    /// <summary>The Go original filed anything that was not "phone" under email. A typo would then
    /// create a login identity nobody can reproduce, so it is rejected here instead.</summary>
    [Theory]
    [InlineData("wechat")]
    [InlineData("emai")]
    [InlineData("")]
    public void AnUnknownIdentityTypeIsRejectedRatherThanDefaultedToEmail(string input) =>
        Should.Throw<ArgumentOutOfRangeException>(() => IdentifierNormalizer.ResolveIdentityType(input));
}
