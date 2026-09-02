using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.SignIn;
using UserSvc.Application.Ports.External;
using UserSvc.Domain.BackOffice;
using Xunit;

namespace UserSvc.UnitTests.BackOffice.SignIn;

/// <summary>
/// The corporate one-time-password door: what the upstream's verdict does, and how an account is
/// matched to or provisioned from an HR record.
/// </summary>
public sealed class BackOfficeStaffOtpSignInTests
{
    private readonly SignInTestHarness _harness = new();

    private static BackOfficeStaffOtpSignInRequest Request(
        string staffId = SignInTestHarness.StaffId,
        string code = SignInTestHarness.OneTimePassword) =>
        new() { StaffId = staffId, OneTimePassword = code };

    /// <summary>
    /// A code the upstream examined and rejected is a sign-in refusal, and it is the only thing the
    /// caller is told: the upstream's own message stays in the log, because it is text another
    /// system wrote about a failed credential check and forwarding it would let that system decide
    /// what this endpoint tells an attacker.
    /// </summary>
    [Fact]
    public async Task ARejectedCodeIsASignInRefusal()
    {
        _harness.StaffDirectory
            .VerifyOtpAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new StaffOtpVerification(false, "E401", "EXPIRED", "the code expired at 09:00"));

        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithStaffOtpAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.OtpVerificationFailed);
        refusal.Message.ShouldNotContain("expired at 09:00");
    }

    /// <summary>
    /// An unreachable upstream is not a failed sign-in. Collapsing the two would tell a user their
    /// code was wrong during an outage and tell no dashboard anything at all.
    /// </summary>
    [Fact]
    public async Task AnUnreachableDirectoryIsNotPhrasedAsAFailedSignIn()
    {
        _harness.StaffDirectory
            .VerifyOtpAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new UpstreamException(ErrorCodes.UpstreamUnavailable, "unreachable"));

        var failure = await Should.ThrowAsync<UpstreamException>(() =>
            _harness.Sut.SignInWithStaffOtpAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        failure.StatusCode.ShouldBe(502);
    }

    /// <summary>
    /// A verified code with no mailbox behind it cannot become an account: the mailbox is the
    /// account's only identity on the password door and its only route for credential mail. It is
    /// the upstream's fault, not the caller's, so 502.
    /// </summary>
    [Fact]
    public async Task AnHrRecordWithNoMailboxIsAnUpstreamFault()
    {
        _harness.StaffDirectory
            .GetStaffProfileAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new StaffProfile(SignInTestHarness.StaffId, "Wang Xiaoming", "", "  ", "A", "D01", "Sales"));

        var failure = await Should.ThrowAsync<UpstreamException>(() =>
            _harness.Sut.SignInWithStaffOtpAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        failure.ErrorCode.ShouldBe(ErrorCodes.UpstreamUnavailable);
    }

    /// <summary>
    /// <b>No domain gate on this door, deliberately.</b> A code the corporate directory has just
    /// verified is the authorization, and the mailbox comes from the HR record rather than from the
    /// caller - there is no client-supplied address for a domain rule to be about.
    /// </summary>
    [Fact]
    public async Task NoDomainRuleAppliesToTheOneTimePasswordDoor()
    {
        _harness.StaffDirectory
            .GetStaffProfileAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new StaffProfile(
                SignInTestHarness.StaffId, "Wang Xiaoming", "wang.xm", "wang@notcorporate.example",
                "A", "D01", "Sales"));

        var response = await _harness.Sut.SignInWithStaffOtpAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        response.SignInTicket.ShouldNotBeNullOrEmpty();
    }

    /// <summary>
    /// <b>A disabled account answers 403 here and 401 on the password door.</b> Inherited from the
    /// service being replaced and kept: on this path the credential was accepted and it is the
    /// account that is closed, which is "stop asking", while on the password path the two are
    /// indistinguishable and 401 is what tells a client to re-authenticate.
    /// </summary>
    [Fact]
    public async Task ADisabledAccountIsRefusedWithFourZeroThreeOnThisDoor()
    {
        var account = _harness.WithPasswordAccount(status: BackendUserStatuses.Disabled);
        _harness.AddIdentity(account.Id, BackendIdentityTypes.Otp, SignInTestHarness.StaffId);

        var refusal = await Should.ThrowAsync<ForbiddenException>(() =>
            _harness.Sut.SignInWithStaffOtpAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.AccountDisabled);
        refusal.StatusCode.ShouldBe(403);
    }

    /// <summary>
    /// Matching starts at the employee number, which survives a rename and a change of mailbox. The
    /// HR record's current address is deliberately not what resolves the account.
    /// </summary>
    [Fact]
    public async Task TheEmployeeNumberResolvesTheAccountEvenAfterTheMailboxChanged()
    {
        var account = _harness.WithPasswordAccount(email: "old.address@liontravel.com");
        _harness.AddIdentity(account.Id, BackendIdentityTypes.Otp, SignInTestHarness.StaffId);

        var response = await _harness.Sut.SignInWithStaffOtpAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        response.UserId.ShouldBe(account.Id);
        _harness.Inserted.ShouldBeNull();
    }

    /// <summary>
    /// A staff member who already has an account from the password door gets the employee number
    /// linked onto it, rather than a rival account created beside it.
    /// </summary>
    [Fact]
    public async Task AMailboxMatchLinksTheEmployeeNumberInsteadOfCreatingASecondAccount()
    {
        var account = _harness.WithPasswordAccount();

        var response = await _harness.Sut.SignInWithStaffOtpAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        response.UserId.ShouldBe(account.Id);
        _harness.Inserted.ShouldBeNull();

        _harness.IdentityRows.ShouldContain(row =>
            row.IdentityType == BackendIdentityTypes.Otp && row.UserId == account.Id);
    }

    /// <summary>
    /// When the employee number and the mailbox point at different accounts, the employee number
    /// wins - it is HR's own key, and the mailbox is the field that moves. Nothing is linked or
    /// created, so the two rows stay as they are for a person to sort out.
    /// </summary>
    [Fact]
    public async Task TheEmployeeNumberBeatsTheMailboxWhenTheyDisagree()
    {
        _harness.WithPasswordAccount();
        _harness.AccountRows.Add(new BackendUser { Id = 999, Status = BackendUserStatuses.Active });
        _harness.AddIdentity(999, BackendIdentityTypes.Otp, SignInTestHarness.StaffId);

        var response = await _harness.Sut.SignInWithStaffOtpAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        response.UserId.ShouldBe(999);
        _harness.Inserted.ShouldBeNull();
    }

    /// <summary>The link step refuses when the employee number belongs to somebody else.</summary>
    [Fact]
    public async Task LinkingAnEmployeeNumberOwnedByAnotherAccountIsRefused()
    {
        var account = _harness.WithPasswordAccount();
        _harness.AccountRows.Add(new BackendUser { Id = 999, Status = BackendUserStatuses.Active });
        _harness.AddIdentity(999, BackendIdentityTypes.Otp, "OTHER-STAFF");

        var conflict = await Should.ThrowAsync<ConflictException>(() =>
            _harness.Onboarding.EnsureOtpIdentityAsync(account, "OTHER-STAFF", CancellationToken.None));

        conflict.ErrorCode.ShouldBe(ErrorCodes.StaffCodeConflict);
        conflict.StatusCode.ShouldBe(409);
    }

    /// <summary>
    /// A staff member with no account is provisioned one from the HR record - <b>ACTIVE and
    /// password-less</b>. Active because the corporate directory has just authenticated them as
    /// current staff, which is the same evidence an administrator would activate them on;
    /// password-less because there is nothing to set one from.
    /// </summary>
    [Fact]
    public async Task AFirstSignInProvisionsAnAccountFromTheHrRecord()
    {
        var response = await _harness.Sut.SignInWithStaffOtpAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        var created = _harness.Inserted.ShouldNotBeNull();
        created.Status.ShouldBe(BackendUserStatuses.Active);
        created.Origin.ShouldBe(BackendUserOrigins.Internal);
        created.HasPassword().ShouldBeFalse();
        created.StaffCode.ShouldBe(SignInTestHarness.StaffId);
        created.DeptNo.ShouldBe("D01");
        created.DeptName.ShouldBe("Sales");

        // "Wang Xiaoming" splits Western-style: the first token is the given name.
        created.FirstName.ShouldBe("Wang");
        created.LastName.ShouldBe("Xiaoming");
        created.Nickname.ShouldBe("wang.xm");

        // Both doors, in one insert, so EF fills user_id from the key it generated.
        created.Identities.Select(identity => identity.IdentityType)
            .ShouldBe([BackendIdentityTypes.Email, BackendIdentityTypes.Otp], ignoreOrder: true);

        response.UserId.ShouldBe(created.Id);
    }

    /// <summary>An HR record with no preferred name falls back to the mailbox's local part, because
    /// a blank display name renders as an empty row on every screen that lists people.</summary>
    [Fact]
    public async Task AStaffMemberWithNoAliasGetsTheMailboxLocalPartAsAHandle()
    {
        _harness.StaffDirectory
            .GetStaffProfileAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new StaffProfile(
                SignInTestHarness.StaffId, "Wang Xiaoming", "   ",
                SignInTestHarness.CorporateEmail, "A", "D01", "Sales"));

        await _harness.Sut.SignInWithStaffOtpAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        _harness.Inserted.ShouldNotBeNull().Nickname.ShouldBe("alice.chen");
    }

    /// <summary>
    /// HR owns these fields, so a rename lands at the next sign-in. The account row is the one that
    /// gives way, not the HR record.
    /// </summary>
    [Fact]
    public async Task TheHrRecordOverwritesTheAccountsNameAndDepartment()
    {
        var account = _harness.WithPasswordAccount();
        _harness.AddIdentity(account.Id, BackendIdentityTypes.Otp, SignInTestHarness.StaffId);

        _harness.StaffDirectory
            .GetStaffProfileAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new StaffProfile(
                SignInTestHarness.StaffId, "Lee Chunhua", "lee.ch",
                SignInTestHarness.CorporateEmail, "A", "D07", "Marketing"));

        await _harness.Sut.SignInWithStaffOtpAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        account.FirstName.ShouldBe("Lee");
        account.LastName.ShouldBe("Chunhua");
        account.Nickname.ShouldBe("lee.ch");
        account.DeptNo.ShouldBe("D07");
        account.DeptName.ShouldBe("Marketing");
    }

    /// <summary>
    /// <b>An empty upstream field means "HR sent nothing", never "clear it".</b> A blank name would
    /// render as an empty row everywhere, and a blank department would drop the label operators use
    /// to find their own team.
    /// </summary>
    [Fact]
    public async Task AnEmptyHrFieldLeavesTheAccountsValueAlone()
    {
        var account = _harness.WithPasswordAccount();
        _harness.AddIdentity(account.Id, BackendIdentityTypes.Otp, SignInTestHarness.StaffId);

        _harness.StaffDirectory
            .GetStaffProfileAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new StaffProfile(
                SignInTestHarness.StaffId, "  ", "  ", SignInTestHarness.CorporateEmail, "A", "  ", "  "));

        await _harness.Sut.SignInWithStaffOtpAsync(
            Request(), BackOfficeSignInContext.None, CancellationToken.None);

        account.FirstName.ShouldBe("Xiaoming");
        account.LastName.ShouldBe("Wang");
        account.Nickname.ShouldBe("wang.xm");
        account.DeptName.ShouldBeNull();
    }

    /// <summary>
    /// The per-employee budget is its own dimension, so a locked-out employee number cannot lock
    /// out the mailbox's password door and vice versa.
    /// </summary>
    [Fact]
    public async Task TheThrottleIsKeyedOnTheEmployeeNumberInItsOwnDimension()
    {
        await _harness.Sut.SignInWithStaffOtpAsync(
            Request(staffId: "  260022  "), BackOfficeSignInContext.None, CancellationToken.None);

        await _harness.Limiter.Received().TryAcquireAsync(
            "backoffice-sign-in-otp",
            SignInTestHarness.StaffId,
            Arg.Any<UserSvc.Application.Ports.Platform.RateLimitPolicy>(),
            Arg.Any<CancellationToken>());
    }

    /// <summary>The code is never presented to the upstream before the throttle has allowed the
    /// attempt: each attempt spends a code somebody was sent.</summary>
    [Fact]
    public async Task TheThrottleRefusesBeforeTheCodeIsPresentedUpstream()
    {
        _harness.WithRateLimitRefusal(TimeSpan.FromSeconds(30));

        await Should.ThrowAsync<RateLimitedException>(() =>
            _harness.Sut.SignInWithStaffOtpAsync(
                Request(), BackOfficeSignInContext.None, CancellationToken.None));

        await _harness.StaffDirectory.DidNotReceive().VerifyOtpAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A deployment with no staff directory fails on this door and nowhere else, with the section
    /// named. The password door keeps working - which is the point of the directory being a
    /// factory rather than a constructor argument.
    /// </summary>
    [Fact]
    public async Task AnUnconfiguredDirectoryFailsThisDoorOnly()
    {
        var harness = new SignInTestHarness();
        harness.WithPasswordAccount();

        var signIns = new BackOfficeSignInAppService(
            harness.Users,
            harness.Identities,
            harness.Onboarding,
            () => throw new AppException(
                ErrorCodes.NotConfigured, "StaffDirectory:ApiKey must be supplied.", 500),
            harness.Contexts,
            harness.Switcher,
            harness.Standing,
            harness.AuditLog,
            harness.Limiter,
            harness.Markers,
            harness.Protector,
            harness.PasswordHasher,
            harness.Tickets,
            harness.UnitOfWork,
            harness.Clock,
            Microsoft.Extensions.Options.Options.Create(harness.AccountOptions),
            Microsoft.Extensions.Options.Options.Create(harness.SignInOptions),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<BackOfficeSignInAppService>.Instance);

        var failure = await Should.ThrowAsync<AppException>(() =>
            signIns.SignInWithStaffOtpAsync(Request(), BackOfficeSignInContext.None, CancellationToken.None));

        failure.ErrorCode.ShouldBe(ErrorCodes.NotConfigured);
        failure.StatusCode.ShouldBe(500);

        // The other door is untouched by the missing capability.
        var response = await signIns.SignInWithPasswordAsync(
            new BackOfficePasswordSignInRequest
            {
                Email = SignInTestHarness.CorporateEmail,
                Password = SignInTestHarness.Password,
            },
            BackOfficeSignInContext.None,
            CancellationToken.None);

        response.SignInTicket.ShouldNotBeNullOrEmpty();
    }
}
