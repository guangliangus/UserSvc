using Microsoft.Extensions.Logging;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.SignIn;
using UserSvc.Application.Features.Registration;
using UserSvc.Domain.BackOffice;
using Xunit;

namespace UserSvc.UnitTests.BackOffice.SignIn;

/// <summary>
/// The cutover-day case: an operator whose password is still a bcrypt hash from the Go service
/// signs in, and the act of signing in migrates the row.
/// <para>
/// The 17 accounts in <c>uam.backend_users</c> are all <c>$2a$10$</c> and nobody holds their
/// plaintexts, so the only moment this service can ever rewrite one is the instant its owner types
/// it correctly. Everything below is about that instant: that it works, that it writes, that it
/// writes only after the sign-in has actually succeeded, and that failing to write does not fail
/// the sign-in.
/// </para>
/// </summary>
public sealed class BackOfficeLegacyPasswordMigrationTests
{
    private readonly SignInTestHarness _harness = new();

    private static BackOfficePasswordSignInRequest Request(
        string email = SignInTestHarness.CorporateEmail,
        string password = SignInTestHarness.Password) =>
        new() { Email = email, Password = password };

    /// <summary>
    /// The whole point. Before the legacy branch existed this answered 401
    /// <c>INVALID_CREDENTIALS</c> with a correct password, indistinguishably from a typo.
    /// </summary>
    [Fact]
    public async Task ALegacyBcryptAccountSignsIn()
    {
        var account = _harness.WithLegacyBcryptPasswordAccount();
        _harness.AddMembership();

        account.PasswordHash.ShouldBe(
            SignInTestHarness.LegacyBcryptHashOfPassword,
            "the test is meaningless if the row is not the legacy one");

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        response.UserId.ShouldBe(57);
    }

    /// <summary>
    /// And the migration: the row is rewritten with what <see cref="PasswordHasher.Hash"/> writes,
    /// through the single-column statement rather than the change tracker.
    /// </summary>
    [Fact]
    public async Task ASuccessfulLegacySignInRewritesTheRowWithArgon2id()
    {
        _harness.WithLegacyBcryptPasswordAccount();
        _harness.AddMembership();

        await _harness.Sut.SignInWithPasswordAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        await _harness.Users.Received(1).UpdatePasswordHashAsync(
            57,
            Arg.Is<string>(hash =>
                PasswordHasher.Identify(hash) == StoredPasswordAlgorithms.Argon2id),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The rewritten hash has to verify the same password, or the migration has locked the operator
    /// out on their <i>second</i> sign-in - a failure that would look nothing like this change and
    /// would be found by a person, not a test.
    /// </summary>
    [Fact]
    public async Task TheRewrittenHashStillVerifiesTheSamePassword()
    {
        _harness.WithLegacyBcryptPasswordAccount();
        _harness.AddMembership();

        string? written = null;
        _harness.Users.UpdatePasswordHashAsync(
                Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                written = call.ArgAt<string>(1);

                return true;
            });

        await _harness.Sut.SignInWithPasswordAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        written.ShouldNotBeNull();
        _harness.PasswordHasher.Verify(SignInTestHarness.Password, written).ShouldBeTrue();
        _harness.PasswordHasher.Verify("not-the-password", written).ShouldBeFalse();
    }

    /// <summary>
    /// A row that is already Argon2id is not rewritten. Rehashing on every sign-in would put an
    /// extra 36 ms derivation and a write on the hot path of every operator, every time, to change
    /// nothing.
    /// </summary>
    [Fact]
    public async Task AnArgon2idAccountIsNotRewritten()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership();

        await _harness.Sut.SignInWithPasswordAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        await _harness.Users.DidNotReceive().UpdatePasswordHashAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A wrong password against a legacy row writes nothing. Otherwise an anonymous caller could
    /// drive one Argon2id hash and one UPDATE per guess.
    /// </summary>
    [Fact]
    public async Task AWrongPasswordAgainstALegacyRowRewritesNothing()
    {
        _harness.WithLegacyBcryptPasswordAccount();

        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(password: "not-the-password"),
                BackOfficeSignInContext.None,
                CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.InvalidCredentials);

        await _harness.Users.DidNotReceive().UpdatePasswordHashAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A correct password on a disabled account verifies and is then refused by the next gate. The
    /// row is not rewritten: a refused request has no business writing to the row it refused, and
    /// the credential is unchanged either way, so the migration simply waits for a sign-in that
    /// succeeds.
    /// </summary>
    [Fact]
    public async Task ADisabledLegacyAccountIsRefusedAndNotRewritten()
    {
        _harness.WithLegacyBcryptPasswordAccount(status: BackendUserStatuses.Disabled);

        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.AccountDisabled);

        await _harness.Users.DidNotReceive().UpdatePasswordHashAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The same for the corporate domain gate, which runs after the password and refuses an
    /// INTERNAL account presenting an outside address.
    /// </summary>
    [Fact]
    public async Task AnOffDomainLegacyAccountIsRefusedAndNotRewritten()
    {
        _harness.WithLegacyBcryptPasswordAccount(email: "alice.chen@gmail.com");

        await Should.ThrowAsync<ForbiddenException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(email: "alice.chen@gmail.com"),
                BackOfficeSignInContext.None,
                CancellationToken.None));

        await _harness.Users.DidNotReceive().UpdatePasswordHashAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// <b>A rehash that cannot be persisted is a migration that happens next time, not a failed
    /// login.</b> The operator's password was correct and they are already signed in; turning a
    /// storage detail into a 500 would recreate the outage this branch exists to prevent, on the
    /// same accounts.
    /// </summary>
    [Fact]
    public async Task AFailedRewriteDoesNotFailTheSignIn()
    {
        _harness.WithLegacyBcryptPasswordAccount();
        _harness.AddMembership();

        _harness.Users.UpdatePasswordHashAsync(
                Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("the connection dropped"));

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        response.UserId.ShouldBe(57);
        response.SignInTicket.ShouldNotBeNullOrEmpty();
    }

    /// <summary>The same when the statement matches no row, which is what a deleted account looks
    /// like between the verify and the write.</summary>
    [Fact]
    public async Task ARewriteThatMatchesNoRowDoesNotFailTheSignIn()
    {
        _harness.WithLegacyBcryptPasswordAccount();
        _harness.AddMembership();

        _harness.Users.UpdatePasswordHashAsync(
                Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        response.UserId.ShouldBe(57);
    }

    /// <summary>
    /// The rewrite does not bump the token version. That lever exists to invalidate outstanding
    /// tokens when a password <i>changes</i>; this is the same secret in a different encoding, and
    /// bumping it would log the operator out of the session they have just created.
    /// </summary>
    [Fact]
    public async Task TheRewriteDoesNotBumpTheTokenVersion()
    {
        _harness.WithLegacyBcryptPasswordAccount();
        _harness.AddMembership();

        await _harness.Sut.SignInWithPasswordAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        await _harness.Users.DidNotReceive().IncrementTokenVersionAsync(
            Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// An account whose stored hash is in no format at all still answers as an ordinary wrong
    /// password, and still writes nothing. This is the case the Error log line is for: the caller
    /// is told nothing, so the log is the only place "nobody can sign in to this account" appears.
    /// </summary>
    [Fact]
    public async Task AnUnreadableStoredHashIsRefusedRewritesNothingAndIsLogged()
    {
        var account = _harness.WithPasswordAccount();
        account.PasswordHash = "sha1:deadbeef";

        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.InvalidCredentials);

        await _harness.Users.DidNotReceive().UpdatePasswordHashAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());

        _harness.Log.MessagesAt(LogLevel.Error)
            .ShouldContain(message => message.Contains("no format this service can read", StringComparison.Ordinal));
    }

    /// <summary>
    /// <b>And a legacy row's wrong password does not log that Error.</b> The line used to fire for
    /// any stored value that was not an Argon2id string, which was right when there was no bcrypt
    /// branch and is wrong now: a bcrypt row verifies. Left as it was, every failed attempt on one
    /// of the 17 migrated-pending accounts would raise an Error claiming no password can ever
    /// verify against it - a false alarm on exactly the rows a cutover is being watched for.
    /// </summary>
    [Fact]
    public async Task AWrongPasswordAgainstALegacyRowIsNotLoggedAsUnreadable()
    {
        _harness.WithLegacyBcryptPasswordAccount();

        await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(password: "not-the-password"),
                BackOfficeSignInContext.None,
                CancellationToken.None));

        _harness.Log.MessagesAt(LogLevel.Error).ShouldBeEmpty();
    }

    /// <summary>
    /// <b>A damaged bcrypt row is logged too, and it did not used to be.</b> A stored value that
    /// still begins <c>$2a$</c> but cannot verify - truncated, or carrying a work factor above the
    /// ceiling - names bcrypt, so a log condition written against
    /// <see cref="PasswordHasher.Identify"/> stayed silent on it. Measured against the running
    /// service: a 29-character <c>$2a$10$</c> row answered 401 with no diagnostic line anywhere,
    /// while the same row with an unrecognised prefix logged one. That is the population this whole
    /// branch exists for, so silence there is the worst place for it.
    /// </summary>
    [Theory]
    [InlineData("$2a$10$K1ZXCl/9EMxJgr.JSAdCE.")]
    [InlineData("$2a$13$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public async Task ADamagedLegacyRowIsRefusedAndLoggedAsUnreadable(string stored)
    {
        var account = _harness.WithPasswordAccount();
        account.PasswordHash = stored;

        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.InvalidCredentials);

        await _harness.Users.DidNotReceive().UpdatePasswordHashAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());

        _harness.Log.MessagesAt(LogLevel.Error)
            .ShouldContain(message => message.Contains("no format this service can read", StringComparison.Ordinal));
    }

    /// <summary>A successful migration says so, at Information: it is the one durable record that a
    /// legacy account has moved, and the count of those lines is how a cutover is watched.</summary>
    [Fact]
    public async Task ASuccessfulMigrationIsLogged()
    {
        _harness.WithLegacyBcryptPasswordAccount();
        _harness.AddMembership();

        _harness.Users.UpdatePasswordHashAsync(
                Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        await _harness.Sut.SignInWithPasswordAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        _harness.Log.MessagesAt(LogLevel.Information)
            .ShouldContain(message =>
                message.Contains("Migrated the legacy password hash", StringComparison.Ordinal)
                && message.Contains("ARGON2ID", StringComparison.Ordinal));
    }
}
