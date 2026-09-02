using System.Globalization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Verification;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Iam;
using UserSvc.Domain.Verification;
using Xunit;

namespace UserSvc.UnitTests.BackOffice;

/// <summary>
/// Back-office registration, self-service password reset and the directory read.
/// <para>
/// Every port is substituted; <see cref="IdentifierProtector"/> and <see cref="PasswordHasher"/>
/// are the real things, because they are pure computation and a fake would only assert that the
/// test's own arithmetic matches itself.
/// </para>
/// </summary>
public sealed class BackOfficeAccountAppServiceTests
{
    private const string CorporateEmail = "alice.chen@liontravel.com";
    private const string Ticket = "ticket-abc";
    private const string Password = "correct-horse-9";

    private readonly IBackendUserRepository _users = Substitute.For<IBackendUserRepository>();
    private readonly IBackendIdentityRepository _identities = Substitute.For<IBackendIdentityRepository>();
    private readonly IVerificationTicketConsumer _tickets = Substitute.For<IVerificationTicketConsumer>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly IIamAuditLogRepository _auditLog = Substitute.For<IIamAuditLogRepository>();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 9, 0, 0, TimeSpan.Zero));

    private readonly IdentifierProtector _protector = new(Options.Create(new IdentifierProtectionOptions
    {
        Pepper = "00112233445566778899aabbccddeeff",
        DataKey = Convert.ToBase64String(new byte[32]),
        KeyVersion = "v3",
    }));

    private readonly PasswordHasher _passwordHasher = new();

    /// <summary>The account handed to the repository, captured as the database would see it: with
    /// the key the insert generated and its identity attached.</summary>
    private BackendUser? _inserted;

    public BackOfficeAccountAppServiceTests()
    {
        _tickets.TryConsumeAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((BackendIdentity?)null);

        _identities.ListActiveByUserIdsAsync(Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);

        _users.UpdatePasswordHashAsync(
                Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        // The substitute has to run the body, or every assertion below would pass against a
        // transaction that never opened.
        _unitOfWork
            .ExecuteInTransactionAsync(Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns(call => call.Arg<Func<CancellationToken, Task>>().Invoke(CancellationToken.None));

        _users.When(repository => repository.Add(Arg.Any<BackendUser>()))
            .Do(call =>
            {
                _inserted = call.Arg<BackendUser>();
                _inserted.Id = 4711;
            });
    }

    private BackOfficeAccountAppService Sut => new(
        _users,
        _identities,
        _tickets,
        new BackOfficeResetTargetGate(_users, _identities, _protector),
        _auditLog,
        _protector,
        _passwordHasher,
        _unitOfWork,
        _clock,
        Options.Create(new BackOfficeAccountOptions()),
        NullLogger<BackOfficeAccountAppService>.Instance);

    // ---------------------------------------------------------------- registration

    [Fact]
    public async Task RegisteringACorporateAddressCreatesAPendingAccountWithItsIdentity()
    {
        var response = await Sut.RegisterAsync(Request(), CancellationToken.None);

        response.Id.ShouldBe(4711);

        // PENDING, not ACTIVE: proving control of a mailbox creates an account, it does not grant
        // it anything. An operator activates it.
        response.Status.ShouldBe(BackendUserStatuses.Pending);

        var account = _inserted.ShouldNotBeNull();
        account.Origin.ShouldBe(BackendUserOrigins.Internal);
        account.Nickname.ShouldBe("alice.chen");
        account.HasPassword().ShouldBeTrue();

        // Nothing on a creation path may hand out the platform.
        account.IsSuperAdmin.ShouldBeFalse();

        var identity = account.Identities.ShouldHaveSingleItem();
        identity.IdentityType.ShouldBe(BackendIdentityTypes.Email);
        identity.IdentifierHash.ShouldBe(_protector.Hash(CorporateEmail));
        _protector.Decrypt(identity.IdentifierCiphertext).ShouldBe(CorporateEmail);
        identity.IdentifierMasked.ShouldBe("a***@liontravel.com");
        identity.KeyVersion.ShouldBe("v3");
    }

    /// <summary>
    /// The password is stored as an Argon2id hash, never as anything reversible. Asserted through
    /// the real hasher rather than by string-matching the format, because what matters is that the
    /// stored value verifies the password and is not the password.
    /// </summary>
    [Fact]
    public async Task RegistrationStoresAVerifiableHashRatherThanThePassword()
    {
        await Sut.RegisterAsync(Request(), CancellationToken.None);

        var stored = _inserted.ShouldNotBeNull().PasswordHash.ShouldNotBeNull();
        stored.ShouldNotContain(Password);
        _passwordHasher.Verify(Password, stored).ShouldBeTrue();
    }

    /// <summary>
    /// The domain gate runs before the ticket is spent, so a request that was never going to
    /// succeed does not consume the caller's proof of mailbox control.
    /// </summary>
    [Fact]
    public async Task RefusesAnAddressOutsideTheCorporateDomains()
    {
        var ex = await Should.ThrowAsync<ForbiddenException>(
            () => Sut.RegisterAsync(Request(email: "alice@example.com"), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.InvalidDomain);
        ex.StatusCode.ShouldBe(403);

        await _tickets.DidNotReceive().TryConsumeAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RefusesAnInvalidTicketBeforeTouchingAnyAccount()
    {
        _tickets.TryConsumeAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.RegisterAsync(Request(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.VerificationFailed);
        _inserted.ShouldBeNull();
        await _identities.DidNotReceive().FindActiveAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>The ticket is spent against the back-office purpose alone, so a consumer ticket for
    /// the same mailbox cannot create an operator account.</summary>
    [Fact]
    public async Task SpendsTheTicketAgainstTheBackOfficePurposeAndTheAddressAsTyped()
    {
        await Sut.RegisterAsync(Request(email: "  Alice.Chen@LionTravel.com  "), CancellationToken.None);

        await _tickets.Received(1).TryConsumeAsync(
            "  Alice.Chen@LionTravel.com  ",
            VerificationPurposes.BackOfficeAuth,
            Ticket,
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// Staff provisioned through the corporate directory already have an account with no local
    /// password. Registering sets one instead of refusing, or they could never use the password
    /// door at all.
    /// </summary>
    [Fact]
    public async Task AttachesAPasswordToAnExistingPasswordlessAccount()
    {
        var existing = ExistingAccount(passwordHash: null);
        GivenExistingIdentityFor(existing);

        var response = await Sut.RegisterAsync(
            Request(firstName: "Alice", lastName: "Chen"), CancellationToken.None);

        response.Id.ShouldBe(existing.Id);
        existing.HasPassword().ShouldBeTrue();
        _passwordHasher.Verify(Password, existing.PasswordHash!).ShouldBeTrue();

        // Nothing new was inserted - the account was already there.
        _users.DidNotReceive().Add(Arg.Any<BackendUser>());
    }

    /// <summary>
    /// A name already on the row came from HR or from an operator; a registration form is the
    /// weakest of the three sources and must not overwrite the others.
    /// </summary>
    [Fact]
    public async Task FillsOnlyTheProfileFieldsTheAccountIsMissing()
    {
        var existing = ExistingAccount(passwordHash: null);
        existing.FirstName = "Alice";
        existing.LastName = null;
        GivenExistingIdentityFor(existing);

        await Sut.RegisterAsync(
            Request(firstName: "Impostor", lastName: "Chen"), CancellationToken.None);

        existing.FirstName.ShouldBe("Alice");
        existing.LastName.ShouldBe("Chen");
    }

    [Fact]
    public async Task RefusesAnAddressThatAlreadyHasAPassword()
    {
        var existing = ExistingAccount(passwordHash: "$argon2id$something");
        GivenExistingIdentityFor(existing);

        var ex = await Should.ThrowAsync<ConflictException>(
            () => Sut.RegisterAsync(Request(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.AlreadyRegistered);
        ex.StatusCode.ShouldBe(409);
    }

    /// <summary>
    /// The unique index is the real guard, so a lost race surfaces as a duplicate rather than as a
    /// constraint name the client cannot act on.
    /// </summary>
    [Fact]
    public async Task ReportsALostRaceAsADuplicateRegistration()
    {
        _unitOfWork
            .ExecuteInTransactionAsync(Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns<Task>(_ => throw new ConflictException(ErrorCodes.Conflict, "unique violation"));

        var ex = await Should.ThrowAsync<ConflictException>(
            () => Sut.RegisterAsync(Request(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.AlreadyRegistered);
    }

    // ---------------------------------------------------------------- password reset

    [Fact]
    public async Task ResettingAPasswordWritesTheHashAndBumpsTheTokenVersion()
    {
        var account = ExistingAccount(passwordHash: "$argon2id$old");
        GivenExistingIdentityFor(account);

        await Sut.ResetPasswordAsync(ResetRequest(), CancellationToken.None);

        await _users.Received(1).UpdatePasswordHashAsync(
            account.Id,
            Arg.Is<string>(hash => _passwordHasher.Verify("new-password-1", hash)),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());

        // Every outstanding access token dies with the old password, in the same transaction.
        await _users.Received(1).IncrementTokenVersionAsync(
            Arg.Is<IReadOnlyList<int>>(ids => ids.Single() == account.Id), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The account may have been disabled between the code being mailed and the ticket being spent,
    /// which is the whole reason the gate runs a second time here.
    /// </summary>
    [Fact]
    public async Task RefusesAResetForADisabledAccount()
    {
        var account = ExistingAccount(passwordHash: "$argon2id$old");
        account.Status = BackendUserStatuses.Disabled;
        GivenExistingIdentityFor(account);

        var ex = await Should.ThrowAsync<ForbiddenException>(
            () => Sut.ResetPasswordAsync(ResetRequest(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.AccountDisabled);
        ex.StatusCode.ShouldBe(403);

        await _users.DidNotReceive().UpdatePasswordHashAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>A pending account is mid-onboarding; setting its password is how onboarding
    /// finishes.</summary>
    [Fact]
    public async Task AllowsAResetForAPendingAccount()
    {
        var account = ExistingAccount(passwordHash: null);
        account.Status = BackendUserStatuses.Pending;
        GivenExistingIdentityFor(account);

        await Sut.ResetPasswordAsync(ResetRequest(), CancellationToken.None);

        await _users.Received(1).UpdatePasswordHashAsync(
            account.Id, Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RefusesAResetForAnAddressWithNoAccount()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.ResetPasswordAsync(ResetRequest(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.Unregistered);
    }

    /// <summary>Phone targets are refused rather than looked up - the back-office reset flow mails
    /// codes to corporate mailboxes and nothing else.</summary>
    [Fact]
    public async Task RefusesAResetTargetThatIsNotAnAddress()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.ResetPasswordAsync(ResetRequest(email: "+886912345678"), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
    }

    /// <summary>
    /// A ticket must never be burned without the password actually changing, so the consumption and
    /// the write share one transaction - and the gate's refusal happens inside it, which is what
    /// rolls the consumption back.
    /// </summary>
    [Fact]
    public async Task SpendsTheResetTicketInsideTheSameTransactionAsTheWrite()
    {
        var account = ExistingAccount(passwordHash: "$argon2id$old");
        GivenExistingIdentityFor(account);

        await Sut.ResetPasswordAsync(ResetRequest(), CancellationToken.None);

        await _unitOfWork.Received(1).ExecuteInTransactionAsync(
            Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>());
        await _tickets.Received(1).TryConsumeAsync(
            CorporateEmail,
            VerificationPurposes.BackOfficeResetPassword,
            Ticket,
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The spec makes SELF_PASSWORD_RESET an audited action, and a log line is not an audit row: a
    /// credential change with no entry is exactly the event the trail exists to answer questions
    /// about. Actor and target are the same account, and the entry is platform-level - a credential
    /// belongs to the account, not to any tenant it happens to work in.
    /// </summary>
    [Fact]
    public async Task ResettingAPasswordWritesTheAuditEntry()
    {
        var account = ExistingAccount(passwordHash: "$argon2id$old");
        account.FirstName = "Alice";
        account.LastName = "Chen";
        GivenExistingIdentityFor(account);

        await Sut.ResetPasswordAsync(ResetRequest(), CancellationToken.None);

        await _auditLog.Received(1).AppendAsync(
            Arg.Is<IamAuditLog>(entry =>
                entry.Action == "SELF_PASSWORD_RESET"
                && entry.ActorUserId == account.Id
                && entry.TargetType == IamAuditTargetTypes.User
                && entry.TargetId == account.Id.ToString(CultureInfo.InvariantCulture)
                && entry.TenantType == IamAuditTenantTypes.Platform

                // Neither spelling of a password belongs anywhere near an audit row.
                && entry.BeforeData == null
                && entry.AfterData == null),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The entry is written after the transaction commits, and its failure is swallowed. Throwing
    /// would tell the user their reset did not happen while the new password already works - and
    /// writing it inside the transaction would let a failed INSERT abort the reset itself, which is
    /// the opposite of best effort.
    /// </summary>
    [Fact]
    public async Task AFailedAuditWriteDoesNotUndoACommittedReset()
    {
        var account = ExistingAccount(passwordHash: "$argon2id$old");
        GivenExistingIdentityFor(account);
        _auditLog.AppendAsync(Arg.Any<IamAuditLog>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException(new InvalidOperationException("the audit table is gone")));

        await Sut.ResetPasswordAsync(ResetRequest(), CancellationToken.None);

        await _users.Received(1).UpdatePasswordHashAsync(
            account.Id, Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>A refused reset writes no audit row - the trail records what happened, and nothing
    /// did.</summary>
    [Fact]
    public async Task ARefusedResetIsNotAudited()
    {
        var account = ExistingAccount(passwordHash: "$argon2id$old");
        account.Status = BackendUserStatuses.Disabled;
        GivenExistingIdentityFor(account);

        await Should.ThrowAsync<ForbiddenException>(
            () => Sut.ResetPasswordAsync(ResetRequest(), CancellationToken.None));

        await _auditLog.DidNotReceive().AppendAsync(Arg.Any<IamAuditLog>(), Arg.Any<CancellationToken>());
    }

    // ---------------------------------------------------------------- directory

    [Fact]
    public async Task TheDirectoryComposesDisplayNamesAndDecryptsAddresses()
    {
        var account = ExistingAccount(passwordHash: null);
        account.FirstName = "Alice";
        account.LastName = "Chen";
        account.Nickname = "alice.c";
        GivenPage(account);
        GivenIdentityRows(EmailIdentityFor(account));

        var response = await Sut.ListAsync(
            new BackOfficeUserListRequest(), visibility: null, CancellationToken.None);

        var row = response.Items.ShouldHaveSingleItem();
        row.Nickname.ShouldBe("Alice Chen");
        row.Email.ShouldBe(CorporateEmail);
        response.Total.ShouldBe(1);
        response.TotalPages.ShouldBe(1);
    }

    /// <summary>
    /// A key rotation must not blank the address column behind a 200 - that reads to an operator as
    /// data loss. The row degrades to the mask instead, which is what the masked column is for.
    /// </summary>
    [Fact]
    public async Task AnUnreadableAddressDegradesToItsMask()
    {
        var account = ExistingAccount(passwordHash: null);
        GivenPage(account);

        var identity = EmailIdentityFor(account);
        identity.IdentifierCiphertext = "not-decryptable";
        GivenIdentityRows(identity);

        var response = await Sut.ListAsync(
            new BackOfficeUserListRequest(), visibility: null, CancellationToken.None);

        response.Items.ShouldHaveSingleItem().Email.ShouldBe("a***@liontravel.com");
    }

    /// <summary>
    /// Who owns the platform is not a tenant administrator's business. The flag is gated on the
    /// caller's own visibility being unrestricted, so it cannot be forgotten at a call site.
    /// </summary>
    [Fact]
    public async Task TheSuperAdministratorFlagIsShownOnlyToAnUnrestrictedCaller()
    {
        var account = ExistingAccount(passwordHash: null);
        account.IsSuperAdmin = true;
        GivenPage(account);

        var unrestricted = await Sut.ListAsync(
            new BackOfficeUserListRequest(), visibility: null, CancellationToken.None);
        unrestricted.Items.ShouldHaveSingleItem().IsSuperAdmin.ShouldBeTrue();

        var scoped = await Sut.ListAsync(
            new BackOfficeUserListRequest(),
            new UserVisibilityFilter([], [new TenantRef("company", "C1")]),
            CancellationToken.None);
        scoped.Items.ShouldHaveSingleItem().IsSuperAdmin.ShouldBeFalse();
    }

    /// <summary>A pager that sends zero is a client defect the operator should not have to read an
    /// error about.</summary>
    [Fact]
    public async Task CorrectsAPageBelowOne()
    {
        GivenPage();

        var response = await Sut.ListAsync(
            new BackOfficeUserListRequest { Page = 0, PageSize = 0 }, null, CancellationToken.None);

        response.Page.ShouldBe(1);
        response.PageSize.ShouldBe(20);
        await _users.Received(1).ListAsync(
            Arg.Is<BackOfficeUserQuery>(query => query.Page == 1 && query.PageSize == 20),
            null,
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ThePickerComposesBothSpellingsOfAName()
    {
        _users.ListOptionsAsync(0, "chen", null, Arg.Any<CancellationToken>())
            .Returns([new BackOfficeUserOption(7, "Alice", "Chen", "alice.c")]);

        var options = await Sut.ListOptionsAsync(0, "chen", null, CancellationToken.None);

        var option = options.ShouldHaveSingleItem();
        option.Id.ShouldBe(7);
        option.Nickname.ShouldBe("Alice Chen");
        option.FullName.ShouldBe("Alice Chen");
    }

    // ---------------------------------------------------------------- fixtures

    private static BackOfficeRegisterRequest Request(
        string email = CorporateEmail,
        string? firstName = null,
        string? lastName = null) =>
        new()
        {
            Email = email,
            Password = Password,
            VerificationTicket = Ticket,
            FirstName = firstName,
            LastName = lastName,
        };

    private static BackOfficePasswordResetRequest ResetRequest(string email = CorporateEmail) =>
        new() { Email = email, NewPassword = "new-password-1", VerificationTicket = Ticket };

    private BackendUser ExistingAccount(string? passwordHash) => new()
    {
        Id = 12,
        PasswordHash = passwordHash,
        Status = BackendUserStatuses.Active,
        Origin = BackendUserOrigins.Internal,
        CreatedAt = _clock.UtcNow,
        UpdatedAt = _clock.UtcNow,
    };

    private void GivenExistingIdentityFor(BackendUser account)
    {
        _identities.FindActiveAsync(
                BackendIdentityTypes.Email, _protector.Hash(CorporateEmail), Arg.Any<CancellationToken>())
            .Returns(EmailIdentityFor(account));

        _users.FindByIdAsync(account.Id, Arg.Any<CancellationToken>()).Returns(account);
    }

    private BackendIdentity EmailIdentityFor(BackendUser account) => new()
    {
        Id = 99,
        UserId = account.Id,
        IdentityType = BackendIdentityTypes.Email,
        IdentifierHash = _protector.Hash(CorporateEmail),
        IdentifierCiphertext = _protector.Encrypt(CorporateEmail),
        IdentifierMasked = BackOfficeIdentifiers.Mask(BackendIdentityTypes.Email, CorporateEmail),
        KeyVersion = _protector.KeyVersion,
        Status = BackendIdentityStatuses.Active,
    };

    private void GivenPage(params BackendUser[] accounts) =>
        _users.ListAsync(Arg.Any<BackOfficeUserQuery>(), Arg.Any<UserVisibilityFilter?>(), Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserPage(accounts, accounts.Length));

    private void GivenIdentityRows(params BackendIdentity[] rows) =>
        _identities.ListActiveByUserIdsAsync(Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>())
            .Returns(rows);
}
