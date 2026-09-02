using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Features.Verification;
using UserSvc.Application.Security;
using Xunit;

namespace UserSvc.UnitTests.Features;

/// <summary>
/// The hashing contract, ported from the Go repository's hash tests. These assertions are what
/// keeps send, verify and consume able to find each other's rows: change any of them and the
/// symptom is not a failing test in production, it is codes that are sent and then never work.
/// </summary>
public sealed class VerificationHashingTests
{
    private readonly IdentifierProtector _protector = TestProtector.Create();

    [Fact]
    public void TheSameCodeAlwaysHashesToTheSameValue() =>
        VerificationHashing.HashSecret(_protector, "123456")
            .ShouldBe(VerificationHashing.HashSecret(_protector, "123456"));

    [Fact]
    public void DifferentCodesHashDifferently() =>
        VerificationHashing.HashSecret(_protector, "123456")
            .ShouldNotBe(VerificationHashing.HashSecret(_protector, "654321"));

    [Fact]
    public void ACodeHashIsLowercaseHexOfThirtyTwoBytes()
    {
        var hash = VerificationHashing.HashSecret(_protector, "123456");

        hash.Length.ShouldBe(64);
        hash.ShouldAllBe(c => char.IsAsciiDigit(c) || (c >= 'a' && c <= 'f'));
    }

    [Fact]
    public void ACodeIsHashedExactlyAsTypedWithNoTrimmingOrCaseFolding() =>
        // A code is a machine-generated secret compared for equality. Normalizing it would widen
        // the set of strings that unlock an account and help nobody who types it correctly.
        VerificationHashing.HashSecret(_protector, " 123456 ")
            .ShouldNotBe(VerificationHashing.HashSecret(_protector, "123456"));

    [Fact]
    public void ATargetIsTrimmedAndLowercasedBeforeHashing() =>
        VerificationHashing.HashTarget(_protector, "  Test@Example.COM  ")
            .ShouldBe(VerificationHashing.HashTarget(_protector, "test@example.com"));

    [Fact]
    public void DifferentTargetsHashDifferently() =>
        VerificationHashing.HashTarget(_protector, "user1@example.com")
            .ShouldNotBe(VerificationHashing.HashTarget(_protector, "user2@example.com"));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void AnAbsentDeviceIdHashesToNothingAtAll(string deviceId) =>
        // Not the hash of the empty string: that would collapse every caller who sent no device
        // header into one shared risk-control counting bucket.
        VerificationHashing.HashDeviceId(_protector, deviceId).ShouldBeEmpty();

    [Fact]
    public void ADeviceIdIsHashedLikeATargetSoTheFallbackCountMatchesStoredRows() =>
        VerificationHashing.HashDeviceId(_protector, " Device-1 ")
            .ShouldBe(VerificationHashing.HashTarget(_protector, "device-1"));
}

/// <summary>
/// A protector wired to fixed, obviously fake key material. The pepper is what makes these hashes
/// deterministic across a test run without any of them being a real one.
/// </summary>
internal static class TestProtector
{
    public static IdentifierProtector Create() => new(Options.Create(new IdentifierProtectionOptions
    {
        Pepper = "00112233445566778899aabbccddeeff",
        DataKey = Convert.ToBase64String(new byte[32]),
        KeyVersion = "v1",
    }));
}
