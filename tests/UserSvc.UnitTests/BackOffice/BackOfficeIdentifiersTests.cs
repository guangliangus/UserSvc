using Shouldly;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Domain.BackOffice;
using Xunit;

namespace UserSvc.UnitTests.BackOffice;

/// <summary>
/// Normalization and masking. The first decides whether two spellings of one mailbox are one
/// account or two; the second decides what an operator sees when a data key cannot be read.
/// </summary>
public sealed class BackOfficeIdentifiersTests
{
    [Theory]
    [InlineData("  Ops@LionTravel.com ", "ops@liontravel.com")]
    [InlineData("ops@liontravel.com", "ops@liontravel.com")]
    public void NormalizesAddressesToOneSpelling(string input, string expected) =>
        BackOfficeIdentifiers.Normalize(BackendIdentityTypes.Email, input).ShouldBe(expected);

    [Fact]
    public void NormalizesPhoneNumbersToDigits() =>
        BackOfficeIdentifiers.Normalize(BackendIdentityTypes.Phone, "+886 912-345-678")
            .ShouldBe("886912345678");

    /// <summary>
    /// The employee number is the corporate directory's key, not ours. It is trimmed and otherwise
    /// left exactly as that system spells it - lowercasing or stripping it would produce a blind
    /// index that never matches the row the directory login created.
    /// </summary>
    [Fact]
    public void LeavesAnEmployeeNumberAloneApartFromTrimming() =>
        BackOfficeIdentifiers.Normalize(BackendIdentityTypes.Otp, "  A260022 ").ShouldBe("A260022");

    [Theory]
    [InlineData("alice.chen@liontravel.com", "a***@liontravel.com")]
    [InlineData("a@liontravel.com", "a***@liontravel.com")]
    public void MasksAnAddressButKeepsItsDomain(string input, string expected) =>
        BackOfficeIdentifiers.Mask(BackendIdentityTypes.Email, input).ShouldBe(expected);

    [Fact]
    public void MasksAPhoneNumberDownToItsLastDigits() =>
        BackOfficeIdentifiers.Mask(BackendIdentityTypes.Phone, "886912345678").ShouldBe("********5678");

    /// <summary>A short value never gives away more than half of itself.</summary>
    [Fact]
    public void NeverRevealsMoreThanHalfOfAShortValue() =>
        BackOfficeIdentifiers.Mask(BackendIdentityTypes.Phone, "1234").ShouldBe("**34");

    [Fact]
    public void MasksAnEmptyValueToAnEmptyValue() =>
        BackOfficeIdentifiers.Mask(BackendIdentityTypes.Email, string.Empty).ShouldBeEmpty();

    [Fact]
    public void GeneratesADistinguishableHandle()
    {
        var handle = BackOfficeIdentifiers.GenerateHandle();

        handle.ShouldStartWith("User_");
        handle.Length.ShouldBe("User_".Length + 8);
        handle.ShouldNotBe(BackOfficeIdentifiers.GenerateHandle());
    }
}
