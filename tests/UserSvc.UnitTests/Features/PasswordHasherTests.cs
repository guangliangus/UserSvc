using System.Text.RegularExpressions;
using Shouldly;
using UserSvc.Application.Features.Registration;
using Xunit;

namespace UserSvc.UnitTests.Features;

/// <summary>
/// The hasher is pure computation, so these run the real Argon2id. Each case costs one derivation
/// at the production parameters, which is the point: a test suite that hashes with cheaper
/// settings would not notice the day the production settings stopped being affordable.
/// </summary>
public sealed partial class PasswordHasherTests
{
    private readonly PasswordHasher _hasher = new();

    [Fact]
    public void APasswordVerifiesAgainstItsOwnHash() =>
        _hasher.Verify("correct horse battery 9", _hasher.Hash("correct horse battery 9")).ShouldBeTrue();

    [Fact]
    public void AnythingElseDoesNot()
    {
        var hash = _hasher.Hash("correct horse battery 9");

        _hasher.Verify("correct horse battery 8", hash).ShouldBeFalse();
        _hasher.Verify(string.Empty, hash).ShouldBeFalse();
        _hasher.Verify("Correct horse battery 9", hash).ShouldBeFalse();
    }

    /// <summary>An empty password is refused where it is cheapest to explain, rather than deep
    /// inside the Argon2 implementation.</summary>
    [Fact]
    public void AnEmptyPasswordIsRefused() =>
        Should.Throw<ArgumentException>(() => _hasher.Hash(string.Empty));

    /// <summary>
    /// Same password, different salt, therefore different digest. Without this, two accounts
    /// sharing a password would be visible as two identical columns - and one cracked hash would
    /// be every account that chose that password.
    /// </summary>
    [Fact]
    public void TheSamePasswordHashesDifferentlyEveryTime() =>
        _hasher.Hash("p4ssword").ShouldNotBe(_hasher.Hash("p4ssword"));

    /// <summary>
    /// The encoded form is what makes the parameters changeable later: it is the PHC string every
    /// Argon2 implementation reads, so the values in force when a row was written travel with it.
    /// </summary>
    [Fact]
    public void TheEncodedHashCarriesTheParametersItWasMadeWith() =>
        PhcFormat().IsMatch(_hasher.Hash("p4ssword")).ShouldBeTrue();

    /// <summary>
    /// Proves the parameters in the stored string are actually used rather than assumed: change
    /// the memory cost and the same password no longer reproduces the digest.
    /// </summary>
    [Fact]
    public void VerificationUsesTheStoredParametersNotTheCurrentConstants()
    {
        var hash = _hasher.Hash("p4ssword");
        var tampered = hash.Replace("m=19456", "m=8192", StringComparison.Ordinal);

        tampered.ShouldNotBe(hash, "the test is meaningless if the memory cost is spelled differently");
        _hasher.Verify("p4ssword", tampered).ShouldBeFalse();
    }

    /// <summary>
    /// A row whose hash cannot be parsed is a row nobody can sign in to, which is the correct
    /// answer. Throwing instead would turn it into a 500 and tell a caller which accounts have
    /// damaged hashes.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("not-a-hash")]
    [InlineData("$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA")]
    [InlineData("$argon2id$v=19$m=19456,t=2$c2FsdHNhbHRzYWx0c2E$aGFzaA")]
    [InlineData("$argon2id$v=19$m=abc,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA")]
    [InlineData("$argon2id$v=19$m=19456,t=2,p=1$not base64!$aGFzaA")]
    public void AnUnreadableStoredHashVerifiesAsFalseRatherThanThrowing(string stored) =>
        _hasher.Verify("p4ssword", stored).ShouldBeFalse();

    /// <summary>
    /// The stored parameters are an instruction to allocate memory, so they are bounded. A row
    /// asking for a terabyte is refused without attempting it - otherwise anyone able to write to
    /// <c>password_hash</c> could turn one sign-in into an out-of-memory kill.
    /// </summary>
    [Theory]
    [InlineData("$argon2id$v=19$m=1073741824,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA")]
    [InlineData("$argon2id$v=19$m=19456,t=2000000,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA")]
    [InlineData("$argon2id$v=19$m=19456,t=2,p=4096$c2FsdHNhbHRzYWx0c2E$aGFzaA")]
    public void StoredParametersBeyondWhatThisServiceWouldEverWriteAreRefused(string stored)
    {
        var started = System.Diagnostics.Stopwatch.StartNew();

        _hasher.Verify("p4ssword", stored).ShouldBeFalse();

        // Generous by two orders of magnitude: the point is only that no derivation was attempted,
        // and one at these parameters could not finish in any amount of time worth waiting for.
        started.Elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(2));
    }

    [GeneratedRegex(@"^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$")]
    private static partial Regex PhcFormat();
}
