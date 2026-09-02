using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.SignIn;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.BackOffice;
using Xunit;

namespace UserSvc.UnitTests.BackOffice.SignIn;

/// <summary>
/// The password door's gates, in the order they run: the throttle, the identity, the password, the
/// account's status, and the corporate domain rule last of all.
/// </summary>
public sealed class BackOfficePasswordSignInTests
{
    private readonly SignInTestHarness _harness = new();

    private static BackOfficePasswordSignInRequest Request(
        string email = SignInTestHarness.CorporateEmail,
        string password = SignInTestHarness.Password) =>
        new() { Email = email, Password = password };

    /// <summary>
    /// An unknown address and a wrong password are indistinguishable to the caller. Telling them
    /// apart turns an anonymous endpoint into a directory of which addresses hold back-office
    /// accounts.
    /// </summary>
    [Fact]
    public async Task AnUnknownAddressAndAWrongPasswordAnswerIdentically()
    {
        _harness.WithPasswordAccount();

        var unknown = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(email: "nobody@liontravel.com"), BackOfficeSignInContext.None, CancellationToken.None));

        var wrong = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(password: "not-the-password"), BackOfficeSignInContext.None, CancellationToken.None));

        unknown.ErrorCode.ShouldBe(ErrorCodes.InvalidCredentials);
        wrong.ErrorCode.ShouldBe(ErrorCodes.InvalidCredentials);
        wrong.Message.ShouldBe(unknown.Message);
        unknown.StatusCode.ShouldBe(401);
    }

    /// <summary>
    /// An unknown address is not audited: there is no account row to anchor an entry to, and
    /// writing one keyed on the address would persist attacker-chosen text into the audit table.
    /// </summary>
    [Fact]
    public async Task AnUnknownAddressIsNotAudited()
    {
        await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        await _harness.AuditLog.DidNotReceive().AppendAsync(
            Arg.Any<UserSvc.Domain.Iam.IamAuditLog>(), Arg.Any<CancellationToken>());
    }

    /// <summary>A wrong password against a real account is audited - with the reason and nothing
    /// about what was typed.</summary>
    [Fact]
    public async Task AWrongPasswordIsAuditedWithItsReasonAndNothingElse()
    {
        _harness.WithPasswordAccount();

        await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(password: "not-the-password"),
                new BackOfficeSignInContext("198.51.100.4", "curl", "req-9"),
                CancellationToken.None));

        await _harness.AuditLog.Received(1).AppendAsync(
            Arg.Is<UserSvc.Domain.Iam.IamAuditLog>(entry =>
                entry.Action == BackOfficeSignInAuditActions.SignInFailed
                && entry.ActorUserId == 57
                && entry.AfterData!.Contains(BackOfficeSignInFailureReasons.InvalidPassword)
                && !entry.AfterData.Contains("not-the-password")
                && entry.Ip == "198.51.100.4"),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A refused sign-in belongs to no tenant, so its audit row states none - not the literal
    /// "platform", which would drop failed sign-ins into every query for platform-scoped
    /// administrative actions.
    /// </summary>
    [Fact]
    public async Task ARefusedSignInIsAuditedAgainstNoTenant()
    {
        _harness.WithPasswordAccount();

        await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(password: "not-the-password"),
                BackOfficeSignInContext.None,
                CancellationToken.None));

        await _harness.AuditLog.Received(1).AppendAsync(
            Arg.Is<UserSvc.Domain.Iam.IamAuditLog>(entry =>
                entry.Action == BackOfficeSignInAuditActions.SignInFailed
                && entry.TenantType == string.Empty
                && entry.TenantCode == string.Empty),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// An account provisioned through the staff directory has no local password. It is refused as
    /// invalid credentials rather than with a code of its own, which would tell an anonymous caller
    /// which door to use for any address they can guess.
    /// </summary>
    [Fact]
    public async Task AnAccountWithNoLocalPasswordIsRefusedAsInvalidCredentials()
    {
        var account = _harness.WithPasswordAccount();
        account.PasswordHash = null;

        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.InvalidCredentials);
    }

    /// <summary>
    /// A stored hash this build cannot read is also invalid credentials to the caller. The service
    /// is expected to say so loudly in its log - the hasher is pure computation and holds no logger,
    /// so nobody else can - but the response must not distinguish it.
    /// </summary>
    [Fact]
    public async Task AnUnreadableStoredHashIsRefusedAsInvalidCredentials()
    {
        var account = _harness.WithPasswordAccount();
        account.PasswordHash = "$2a$10$notanargon2idhash";

        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.InvalidCredentials);
    }

    /// <summary>A disabled account is 401 on this door. The one-time-password door answers 403 for
    /// the same account - see the note there for why the asymmetry is kept.</summary>
    [Fact]
    public async Task ADisabledAccountIsRefusedWithFourZeroOneOnThePasswordDoor()
    {
        _harness.WithPasswordAccount(status: BackendUserStatuses.Disabled);

        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.AccountDisabled);
        refusal.StatusCode.ShouldBe(401);
    }

    /// <summary>
    /// A status the database CHECK constraint does not allow is refused rather than read as
    /// PENDING. That branch exists precisely because it should be unreachable: a hand-written
    /// UPDATE, or a status added to the constraint and not to this code, must fail closed.
    /// </summary>
    [Fact]
    public async Task AStatusThisBuildDoesNotRecogniseIsRefused()
    {
        _harness.WithPasswordAccount(status: "SUSPENDED");

        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.AccountInactive);
    }

    /// <summary>
    /// The corporate domain rule applies to an internal account and names the allow-list, which is
    /// configuration a client renders rather than a secret. By this point the caller has already
    /// proved they hold the password.
    /// </summary>
    [Fact]
    public async Task AnInternalAccountMustUseACorporateAddress()
    {
        _harness.WithPasswordAccount(
            email: "alice@gmail.com", origin: BackendUserOrigins.Internal);

        var refusal = await Should.ThrowAsync<ForbiddenException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(email: "alice@gmail.com"), BackOfficeSignInContext.None, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.InvalidDomain);
        refusal.Message.ShouldContain("@liontravel.com");

        await _harness.AuditLog.Received(1).AppendAsync(
            Arg.Is<UserSvc.Domain.Iam.IamAuditLog>(entry =>
                entry.AfterData!.Contains(BackOfficeSignInFailureReasons.InvalidDomain)),
            Arg.Any<CancellationToken>());
    }

    /// <summary>An external partner authenticates with whatever mailbox they have. The gate reads
    /// the account's origin, not the address.</summary>
    [Fact]
    public async Task AnExternalAccountMayUseAnyAddress()
    {
        _harness.WithPasswordAccount(
            email: "partner@example.net", origin: BackendUserOrigins.External);

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request(email: "partner@example.net"), BackOfficeSignInContext.None, CancellationToken.None);

        response.Origin.ShouldBe(BackendUserOrigins.External);
        response.SignInTicket.ShouldNotBeNullOrEmpty();
    }

    /// <summary>
    /// The domain rule runs after the identity lookup. An address that belongs to nobody must
    /// answer "invalid credentials" and never "wrong domain", or the difference confirms which
    /// addresses exist.
    /// </summary>
    [Fact]
    public async Task AnUnknownNonCorporateAddressIsNotToldAboutTheDomainRule()
    {
        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(email: "stranger@gmail.com"), BackOfficeSignInContext.None, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.InvalidCredentials);
    }

    /// <summary>
    /// The lockout check runs before anything else, because everything after it costs a database
    /// read or 50 ms of Argon2. Its refusal carries the wait, which is the only thing that turns a
    /// 429 into something a client can act on.
    /// </summary>
    [Fact]
    public async Task TheLockoutCheckRefusesBeforeAnythingIsRead()
    {
        _harness.WithPasswordAccount();
        _harness.WithRateLimitRefusal(TimeSpan.FromSeconds(42));

        var refusal = await Should.ThrowAsync<RateLimitedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.RateLimitExceeded);
        refusal.RetryAfter.ShouldBe(TimeSpan.FromSeconds(42));

        await _harness.Identities.DidNotReceive().FindActiveAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A refused window stops there rather than reading the next one. It costs no budget now that
    /// the gate is a read, but the ordering is still the contract: the first refusal is the one the
    /// caller is told about, and it decides which of the two messages they get.
    /// </summary>
    [Fact]
    public async Task ARefusedWindowDoesNotEvaluateTheNextOne()
    {
        _harness.WithPasswordAccount();
        _harness.WithRateLimitRefusal(TimeSpan.FromSeconds(5));

        await Should.ThrowAsync<RateLimitedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        await _harness.Limiter.Received(1).PeekAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<RateLimitPolicy>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The counter is keyed on the normalized address and on a back-office dimension of its own, so
    /// one mailbox used on both planes cannot be locked out of the back office by hammering
    /// consumer sign-in.
    /// </summary>
    [Fact]
    public async Task TheLockoutCheckIsKeyedOnTheNormalizedAddressInABackOfficeDimension()
    {
        _harness.WithPasswordAccount();

        await _harness.Sut.SignInWithPasswordAsync(
            Request(email: "  Alice.Chen@LionTravel.com "), BackOfficeSignInContext.None, CancellationToken.None);

        await _harness.Limiter.Received().PeekAsync(
            "backoffice-sign-in",
            SignInTestHarness.CorporateEmail,
            Arg.Any<RateLimitPolicy>(),
            Arg.Any<CancellationToken>());
    }
}
