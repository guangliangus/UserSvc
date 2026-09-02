using System.Text.RegularExpressions;
using Shouldly;
using UserSvc.Application.Features.Registration;
using Xunit;

namespace UserSvc.UnitTests.Features;

/// <summary>
/// The hasher is pure computation, so these run the real Argon2id. Each case costs one derivation
/// at the production parameters, which is the point: a test suite that hashes with cheaper
/// settings would not notice the day the production settings stopped being affordable.
/// <para>
/// The legacy bcrypt cases carry the same weight for a different reason. Every malformed input
/// below was produced by probing the bcrypt library directly, and it throws for almost all of
/// them - a bare prefix, a truncated string, an unknown revision, a cost outside its range, an
/// empty value. This class turns each of those into <c>false</c>, and every one of them is on the
/// path of an ordinary wrong-password attempt, so a case that starts throwing again is a 500 on
/// the back office's front door.
/// </para>
/// </summary>
public sealed partial class PasswordHasherTests
{
    /// <summary>
    /// The plaintext behind every <c>Bcrypt*</c> fixture below.
    /// </summary>
    private const string LegacyPassword = "correct horse battery 9";

    /// <summary>
    /// A bcrypt hash of <see cref="LegacyPassword"/> in the exact shape the Go service left in
    /// <c>uam.backend_users</c>: revision <c>2a</c>, cost 10, 60 characters.
    /// <para>
    /// <b>Generated here, not copied from the live table.</b> All 17 production rows are
    /// <c>$2a$10$</c> and 60 characters long - verified against the live database - so this is
    /// structurally the same string, and the real ones are hashes of passwords still in use by
    /// real people. Committing one to a public repository would hand an offline cracker a target
    /// for no test coverage that this does not already give.
    /// </para>
    /// </summary>
    private const string Bcrypt2a10 = "$2a$10$qdf2d/ty3W/sq89KoJ6cYexZSve/QJd7MUWiNjugh4xblvq7aNp.G";

    /// <summary>The same password under revision <c>2b</c>, the current OpenBSD one.</summary>
    private const string Bcrypt2b10 = "$2b$10$Qu1Hhj2NlmMccV/ULo.w7OXtSnBTWamzuL0fkMEzgswnek8BHr.nW";

    /// <summary>The same password under revision <c>2y</c>, crypt_blowfish's fixed revision.</summary>
    private const string Bcrypt2y10 = "$2y$10$xAEiOlga81Gb4lp22Rolc.EP7MRZAzyy8Qf3IA.2Q4DJtlog.XjeS";

    /// <summary>Cost 12, the highest the hasher will honour.</summary>
    private const string Bcrypt2a12 = "$2a$12$ukoNGBhDXzv4RT75.Z9zGeHzxZer.KvBs0VAVx7TQK6a8tZcBuB1y";

    /// <summary>Cost 13, one past the ceiling: a correct password against it must still fail.</summary>
    private const string Bcrypt2a13 = "$2a$13$4nTpZTEOXaHxVrw1D6x.u.WM5CUPxk8r.5/mDdy3L7uTBl4KkqYfu";

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

    // ------------------------------------------------------------------ the legacy bcrypt branch

    /// <summary>
    /// The reason the branch exists. Without it these three answer false and 17 back-office
    /// operators are locked out on cutover day with a 401 that looks exactly like a typo.
    /// </summary>
    [Theory]
    [InlineData(Bcrypt2a10)]
    [InlineData(Bcrypt2b10)]
    [InlineData(Bcrypt2y10)]
    public void ALegacyBcryptHashVerifiesItsOwnPassword(string stored) =>
        _hasher.Verify(LegacyPassword, stored).ShouldBeTrue();

    /// <summary>
    /// And the branch is a verification, not an acceptance. A wrong password against a legacy row
    /// has to fail as ordinarily as one against an Argon2id row.
    /// </summary>
    [Theory]
    [InlineData(Bcrypt2a10)]
    [InlineData(Bcrypt2b10)]
    [InlineData(Bcrypt2y10)]
    public void ALegacyBcryptHashRefusesEverythingElse(string stored)
    {
        _hasher.Verify("correct horse battery 8", stored).ShouldBeFalse();
        _hasher.Verify(LegacyPassword.ToUpperInvariant(), stored).ShouldBeFalse();
        _hasher.Verify(string.Empty, stored).ShouldBeFalse();
    }

    /// <summary>
    /// A round trip through the same library that wrote the production rows, so the fixtures above
    /// are not the only thing standing between this branch and a library change.
    /// </summary>
    [Fact]
    public void AFreshlyMadeBcryptHashVerifiesToo()
    {
        var made = BCrypt.Net.BCrypt.HashPassword("a-different-password-1", 10);

        made.ShouldStartWith("$2");
        made.Length.ShouldBe(60);
        _hasher.Verify("a-different-password-1", made).ShouldBeTrue();
        _hasher.Verify("a-different-password-2", made).ShouldBeFalse();
    }

    /// <summary>
    /// bcrypt truncates at 72 bytes, so a longer password is a real password to it. The point here
    /// is only that a long candidate against a legacy row answers false without the library
    /// throwing on the way.
    /// </summary>
    [Fact]
    public void AnOverlongCandidateAgainstALegacyHashIsRefusedRatherThanThrowing() =>
        _hasher.Verify(new string('x', 200), Bcrypt2a10).ShouldBeFalse();

    /// <summary>
    /// The work factor is bounded for the same reason the Argon2id parameters are: a stored row is
    /// an instruction to spend 2^cost key expansions, the format allows 31, and a probe at cost 31
    /// never returned - it had to be killed. Cost 12 is honoured, 13 is not.
    /// </summary>
    [Fact]
    public void ABcryptWorkFactorBeyondTheCeilingIsRefusedWithoutSpendingIt()
    {
        _hasher.Verify(LegacyPassword, Bcrypt2a12).ShouldBeTrue("cost 12 is inside the ceiling");

        var started = System.Diagnostics.Stopwatch.StartNew();

        _hasher.Verify(LegacyPassword, Bcrypt2a13).ShouldBeFalse();

        // Cost 13 is roughly 400 ms of real work on the machine these numbers were taken on, and
        // cost 31 is unbounded. The assertion is that none of it was attempted, so the bound is
        // generous: only a refusal that actually derived could exceed it.
        started.Elapsed.ShouldBeLessThan(TimeSpan.FromMilliseconds(150));
    }

    /// <summary>
    /// Every one of these makes the bcrypt library throw when handed to it directly - measured, and
    /// with five different exception types between them. A sign-in attempt reaches this method for
    /// any row whose hash starts with a bcrypt prefix, so each has to come back as an ordinary
    /// false.
    /// <para>
    /// The cases divide into two halves, and both halves are needed. The first six are stopped by
    /// this class's own format checks - a length that is not 60, a work factor that is not two
    /// digits or is past the ceiling, a separator in the wrong place - and never reach the library
    /// at all. <c>$2a$03$</c> is the other half: it is 60 characters with a well-formed two-digit
    /// factor, so it passes every check here and then throws inside the library, whose own floor is
    /// 4. It is the case that makes the catch load-bearing rather than decorative, and it was found
    /// by deleting the catch and watching nothing fail.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("$2a$")]
    [InlineData("$2a$10$")]
    [InlineData("$2a$10$abc")]
    [InlineData("$2a$99$qdf2d/ty3W/sq89KoJ6cYexZSve/QJd7MUWiNjugh4xblvq7aNp.G")]
    [InlineData("$2a$aa$qdf2d/ty3W/sq89KoJ6cYexZSve/QJd7MUWiNjugh4xblvq7aNp.G")]
    [InlineData("$2a$+9$qdf2d/ty3W/sq89KoJ6cYexZSve/QJd7MUWiNjugh4xblvq7aNp.G")]
    [InlineData("$2a$10.qdf2d/ty3W/sq89KoJ6cYexZSve/QJd7MUWiNjugh4xblvq7aNp.G")]
    [InlineData("$2a$10$qdf2d/ty3W/sq89KoJ6cYexZSve/QJd7MUWiNjugh4xblvq7aNp.G-too-long")]
    [InlineData("$2a$10$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")]
    [InlineData("$2a$03$qdf2d/ty3W/sq89KoJ6cYexZSve/QJd7MUWiNjugh4xblvq7aNp.G")]
    [InlineData("$2a$01$qdf2d/ty3W/sq89KoJ6cYexZSve/QJd7MUWiNjugh4xblvq7aNp.G")]
    public void AMalformedBcryptStringVerifiesAsFalseRatherThanThrowing(string stored) =>
        _hasher.Verify(LegacyPassword, stored).ShouldBeFalse();

    /// <summary>
    /// The prefix list is an allow-list, not a pattern. <c>$2x$</c> is the revision that reproduces
    /// crypt_blowfish's 8-bit bug on purpose; Go's bcrypt never wrote one and the live table holds
    /// none, so it is refused rather than verified against a key schedule known to be broken.
    /// <c>$2$</c> and <c>$2z$</c> are not bcrypt revisions at all.
    /// </summary>
    [Theory]
    [InlineData("$2x$10$qdf2d/ty3W/sq89KoJ6cYexZSve/QJd7MUWiNjugh4xblvq7aNp.G")]
    [InlineData("$2z$10$qdf2d/ty3W/sq89KoJ6cYexZSve/QJd7MUWiNjugh4xblvq7aNp.G")]
    [InlineData("$2$10$qdf2d/ty3W/sq89KoJ6cYexZSve/QJd7MUWiNjugh4xblvq7aNp.G")]
    [InlineData("$1$salt$hash")]
    public void AnUnsupportedRevisionIsNotTreatedAsBcrypt(string stored)
    {
        PasswordHasher.Identify(stored).ShouldBe(StoredPasswordAlgorithms.Unknown);
        _hasher.Verify(LegacyPassword, stored).ShouldBeFalse();
    }

    // ------------------------------------------------------------------ which algorithm, and why

    /// <summary>
    /// The one question the sign-in flow asks that <see cref="PasswordHasher.Verify"/> cannot
    /// answer: not "is this password right" but "which branch answered, and does this row need
    /// rewriting". A stored string carries its own algorithm name, which is why no
    /// <c>password_algo</c> column is needed to route it.
    /// </summary>
    [Theory]
    [InlineData(Bcrypt2a10, StoredPasswordAlgorithms.Bcrypt)]
    [InlineData(Bcrypt2b10, StoredPasswordAlgorithms.Bcrypt)]
    [InlineData(Bcrypt2y10, StoredPasswordAlgorithms.Bcrypt)]
    [InlineData("$2a$", StoredPasswordAlgorithms.Bcrypt)]
    [InlineData("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA", StoredPasswordAlgorithms.Argon2id)]
    [InlineData("$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA", StoredPasswordAlgorithms.Unknown)]
    [InlineData("", StoredPasswordAlgorithms.Unknown)]
    [InlineData(null, StoredPasswordAlgorithms.Unknown)]
    [InlineData("not-a-hash", StoredPasswordAlgorithms.Unknown)]
    public void IdentifyReadsTheAlgorithmOffTheStoredStringItself(
        string? stored, StoredPasswordAlgorithms expected) =>
        PasswordHasher.Identify(stored).ShouldBe(expected);

    /// <summary>
    /// <see cref="PasswordHasher.Identify"/> names a <i>format</i>, not a verdict: a bcrypt prefix
    /// with nothing usable behind it is still routed to the bcrypt branch, which then refuses it.
    /// The distinction matters at the call site, and getting it wrong there was a silent lockout:
    /// a truncated bcrypt string is a row nobody can ever sign in to, so the sign-in flow asks
    /// <see cref="PasswordHasher.IsReadable"/> rather than this method before deciding whether to
    /// shout about it.
    /// </summary>
    [Fact]
    public void IdentifyNamesTheFormatAndNotWhetherItWillVerify()
    {
        PasswordHasher.Identify("$2a$10$abc").ShouldBe(StoredPasswordAlgorithms.Bcrypt);
        _hasher.Verify(LegacyPassword, "$2a$10$abc").ShouldBeFalse();
    }

    /// <summary>
    /// What the hasher writes is always Argon2id, so nothing it produces is ever a migration
    /// candidate. This is the property that makes the legacy set a one-way ratchet.
    /// </summary>
    [Fact]
    public void NothingThisHasherWritesIsALegacyHash() =>
        PasswordHasher.Identify(_hasher.Hash("p4ssword")).ShouldBe(StoredPasswordAlgorithms.Argon2id);

    /// <summary>
    /// <see cref="PasswordHasher.IsReadable"/> answers the question the sign-in flow's Error log
    /// actually needs - "could anything ever verify against this?" - which
    /// <see cref="PasswordHasher.Identify"/> does not. Every case below names an algorithm this
    /// service has, so <c>Identify</c> calls it readable; none of them can ever verify.
    /// </summary>
    [Theory]
    // Bcrypt-shaped but structurally impossible.
    [InlineData("$2a$")]
    [InlineData("$2a$10$")]
    [InlineData("$2a$10$K1ZXCl/9EMxJgr.JSAdCE.")]
    [InlineData("$2b$10$tooshort")]
    // A work factor above the ceiling: 60 characters and well formed, refused on cost alone.
    [InlineData("$2a$13$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("$2a$31$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    // Argon2id-shaped but structurally impossible.
    [InlineData("$argon2id$v=19$m=19456")]
    [InlineData("$argon2id$v=19$m=19456,t=2,p=1$!!!!$!!!!")]
    [InlineData("$argon2id$v=19$m=1073741824,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA")]
    public void AValueThatNamesAnAlgorithmButCannotVerifyIsNotReadable(string stored)
    {
        PasswordHasher.Identify(stored).ShouldNotBe(StoredPasswordAlgorithms.Unknown);
        PasswordHasher.IsReadable(stored).ShouldBeFalse();
        _hasher.Verify(LegacyPassword, stored).ShouldBeFalse();
    }

    /// <summary>Absent and unrecognised values are unreadable too, so the one predicate covers
    /// every row a caller might hand it straight from a nullable column.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-hash")]
    [InlineData("$2x$10$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void AnAbsentOrUnrecognisedValueIsNotReadable(string? stored) =>
        PasswordHasher.IsReadable(stored).ShouldBeFalse();

    /// <summary>The two formats this service really stores are readable, which is what keeps the
    /// predicate from being a blanket "false" that would log an Error on every failed sign-in.</summary>
    [Theory]
    [InlineData(Bcrypt2a10)]
    [InlineData(Bcrypt2b10)]
    [InlineData(Bcrypt2y10)]
    public void ARealLegacyHashIsReadable(string stored) =>
        PasswordHasher.IsReadable(stored).ShouldBeTrue();

    /// <summary>Including what this hasher writes itself - the case that would turn every wrong
    /// password on a healthy modern account into a false "unreadable row" alarm.</summary>
    [Fact]
    public void WhatTheHasherWritesIsReadable() =>
        PasswordHasher.IsReadable(_hasher.Hash("p4ssword")).ShouldBeTrue();

    /// <summary>
    /// The legacy branch may not cost more than one Argon2id verification, <b>directionally</b>:
    /// this is the guard that catches somebody making Argon2id cheaper.
    /// <para>
    /// <b>Why it is here and not on the sign-in door.</b> The door's
    /// <c>ALegacyRowsRefusalStaysWithinOneVerifyOfTheEqualisedPaths</c> compares
    /// <c>max/min</c> of two whole sign-ins, and neither half of that can catch this regression:
    /// <c>max/min</c> is not monotonic in the Argon2id cost (at the shipped parameters Argon2id is
    /// the <i>slower</i> side, so cheapening it first walks the ratio down to 1.0 before it climbs
    /// again), and a whole sign-in's fixed cost compresses every ratio towards 1. Measured: halving
    /// <c>MemoryKibibytes</c> moved that test from 1.39 to 1.49 against a bound of 2.5 - green,
    /// while the oracle it exists to bound had doubled. Here the same halving takes this ratio from
    /// about 1.4 to about 2.8.
    /// </para>
    /// <para>
    /// <b>Directional on purpose.</b> Only <c>bcrypt / argon2id</c> is asserted. bcrypt's cost is
    /// fixed by data this service cannot write, so the only end of this ratio that can move is
    /// ours, and the only direction that re-opens the account-existence oracle on the password door
    /// is Argon2id getting cheaper.
    /// </para>
    /// <para>
    /// <b>Minimum of five, and a loose bound, for the reason the other guard records:</b> a
    /// thousand tests run in parallel and every one that hashes holds 19 MiB, so contention can
    /// only push a sample up. The minimum is the statistic that resists it, and 2.5 leaves room for
    /// a loaded machine while still catching a halving.
    /// </para>
    /// </summary>
    [Fact]
    public void TheLegacyBranchStaysWithinOneVerifyOfTheAlgorithmWeWrite()
    {
        var argon2id = _hasher.Hash(LegacyPassword);

        PasswordHasher.Identify(Bcrypt2a10).ShouldBe(StoredPasswordAlgorithms.Bcrypt);
        PasswordHasher.Identify(argon2id).ShouldBe(StoredPasswordAlgorithms.Argon2id);

        // Interleaved, so a burst of load lands on both rather than on one.
        var argonSamples = new List<double>();
        var bcryptSamples = new List<double>();

        for (var round = 0; round < 5; round++)
        {
            argonSamples.Add(Elapsed(() => _hasher.Verify("wrong-password", argon2id)));
            bcryptSamples.Add(Elapsed(() => _hasher.Verify("wrong-password", Bcrypt2a10)));
        }

        var argonBest = argonSamples.Min();
        var bcryptBest = bcryptSamples.Min();

        argonBest.ShouldBeGreaterThan(
            5, $"an Argon2id verification must still cost a derivation; it was {argonBest:F1} ms");

        (bcryptBest / argonBest).ShouldBeLessThan(
            2.5,
            $"a legacy bcrypt verification may not cost more than 2.5 Argon2id verifications, or "
            + $"the account-existence oracle on the back-office password door is readable again "
            + $"for unmigrated rows; Argon2id {argonBest:F1} ms against bcrypt {bcryptBest:F1} ms. "
            + $"If this went red because the Argon2id constants were lowered, that is the "
            + $"regression it exists for - see BackOfficePasswordTiming.");
    }

    private static double Elapsed(Action act)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        act();
        sw.Stop();
        return sw.Elapsed.TotalMilliseconds;
    }

    [GeneratedRegex(@"^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$")]
    private static partial Regex PhcFormat();
}
