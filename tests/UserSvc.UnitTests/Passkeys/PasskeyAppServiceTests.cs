using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Passkeys;
using UserSvc.Application.Ports.Auth;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Application.Security;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Users;
using Xunit;

namespace UserSvc.UnitTests.Passkeys;

/// <summary>
/// The decisions the protocol does not make: who may add a credential, what a caller learns about
/// credentials that are not theirs, and when removing one would lock somebody out for good.
/// <para>
/// The cryptography is substituted here and tested for real in
/// <see cref="Fido2WebAuthnCeremonyTests"/>. What this file must not do is substitute the clone
/// check away and then claim to test it - so the clone cases below assert the two things that are
/// this layer's own responsibility: that a refusal from the verifier is passed on as
/// <c>PASSKEY_POSSIBLE_CLONE</c> rather than swallowed, and that the domain rule stops a
/// regressed counter even when the verifier accepts it.
/// </para>
/// </summary>
public sealed class PasskeyAppServiceTests
{
    private const int UserId = 42;
    private const string Flow = "pklogin_deadbeef";

    private static readonly byte[] CredentialId = [1, 2, 3, 4];

    private readonly IUserPasskeyRepository _passkeys = Substitute.For<IUserPasskeyRepository>();
    private readonly IPasskeyIdentityLink _identityLink = Substitute.For<IPasskeyIdentityLink>();
    private readonly IWebAuthnCeremony _ceremony = Substitute.For<IWebAuthnCeremony>();
    private readonly IUserRepository _users = Substitute.For<IUserRepository>();
    private readonly IUserIdentityRepository _identities = Substitute.For<IUserIdentityRepository>();
    private readonly IRateLimiter _rateLimiter = Substitute.For<IRateLimiter>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 1, 12, 0, 0, TimeSpan.Zero));

    private readonly IdentifierProtector _protector = new(Options.Create(new IdentifierProtectionOptions
    {
        Pepper = "00112233445566778899aabbccddeeff",
        DataKey = Convert.ToBase64String(new byte[32]),
        KeyVersion = "v3",
    }));

    public PasskeyAppServiceTests()
    {
        _users.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(new User { Id = UserId, Status = UserStatuses.Active, Nickname = "alan" });

        _rateLimiter
            .TryAcquireAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<RateLimitPolicy>(), Arg.Any<CancellationToken>())
            .Returns(new RateLimitDecision(true, 19, TimeSpan.Zero));

        _unitOfWork
            .ExecuteInTransactionAsync(Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns(call => call.Arg<Func<CancellationToken, Task>>().Invoke(CancellationToken.None));

        _ceremony
            .BeginLoginAsync(Arg.Any<WebAuthnLoginTarget>(), Arg.Any<CancellationToken>())
            .Returns(new WebAuthnCeremonyStart(Flow, """{"challenge":"AAAA"}"""));

        _ceremony
            .BeginRegistrationAsync(
                Arg.Any<WebAuthnUserEntity>(),
                Arg.Any<IReadOnlyList<WebAuthnCredentialReference>>(),
                Arg.Any<string?>(),
                Arg.Any<CancellationToken>())
            .Returns(new WebAuthnCeremonyStart("pkreg_1", """{"challenge":"AAAA"}"""));
    }

    private PasskeyAppService Sut => new(
        _passkeys,
        _identityLink,
        _ceremony,
        _users,
        _identities,
        _rateLimiter,
        _protector,
        _unitOfWork,
        _clock,
        NullLogger<PasskeyAppService>.Instance);

    // ---------------------------------------------------------------- clone detection

    [Fact]
    public async Task AVerifierThatReportsACloneIsNotSwallowed()
    {
        var stored = StoredPasskey(signCount: 5);
        GivenAssertionFor(stored);

        _ceremony
            .CompleteLoginAsync(
                Arg.Any<WebAuthnAssertionRequest>(),
                Arg.Any<WebAuthnStoredCredential>(),
                Arg.Any<CancellationToken>())
            .Returns<Task<WebAuthnAssertion>>(_ => throw new UnauthorizedException(
                ErrorCodes.PasskeyPossibleClone, "cloned"));

        var ex = await Should.ThrowAsync<UnauthorizedException>(
            () => Sut.FinishLoginAsync(LoginRequest(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyPossibleClone);
        ex.StatusCode.ShouldBe(401);

        // Nothing about the credential was written. In particular the counter still holds the
        // genuine authenticator's value, so its next login still works.
        stored.SignCount.ShouldBe(5);
        stored.LastUsedAt.ShouldBeNull();
        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ARegressedCounterIsRefusedEvenIfTheVerifierAcceptsIt()
    {
        var stored = StoredPasskey(signCount: 9);
        GivenAssertionFor(stored);

        // Models a verifier that has lost its own counter check - a library upgrade, a swapped
        // implementation. The domain rule is the copy that cannot be lost, and this is the test
        // that says so.
        GivenVerifiedAssertion(signCount: 4, backupState: true);

        var ex = await Should.ThrowAsync<UnauthorizedException>(
            () => Sut.FinishLoginAsync(LoginRequest(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyPossibleClone);
        stored.SignCount.ShouldBe(9);
        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AZeroCounterAuthenticatorSignsInAndTheStoredCounterStands()
    {
        var stored = StoredPasskey(signCount: 0);
        GivenAssertionFor(stored);
        GivenVerifiedAssertion(signCount: 0, backupState: false);

        var response = await Sut.FinishLoginAsync(LoginRequest(), CancellationToken.None);

        response.UserId.ShouldBe(UserId);
        response.PasskeyId.ShouldBe(stored.Id);
        response.AuthenticatedAt.ShouldBe(_clock.UtcNow);
        stored.LastUsedAt.ShouldBe(_clock.UtcNow);
        await _unitOfWork.Received(1).SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ASuccessfulLoginCommitsTheAdvancedCounter()
    {
        var stored = StoredPasskey(signCount: 5);
        GivenAssertionFor(stored);
        GivenVerifiedAssertion(signCount: 6, backupState: true);

        await Sut.FinishLoginAsync(LoginRequest(), CancellationToken.None);

        stored.SignCount.ShouldBe(6);
        stored.BackupState.ShouldBeTrue();

        // Committed, not best-effort: a counter that silently fails to advance is a clone check
        // that has silently stopped working.
        await _unitOfWork.Received(1).SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    // ---------------------------------------------------------------- login answers

    [Fact]
    public async Task AnUnknownCredentialIsAnsweredDistinctlyFromAFailedAssertion()
    {
        _ceremony
            .TakeAssertionAsync(Flow, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new WebAuthnAssertionRequest("{}", null, CredentialId, "{}"));

        _passkeys.FindByCredentialIdAsync(CredentialId, Arg.Any<CancellationToken>())
            .Returns((UserPasskey?)null);

        var ex = await Should.ThrowAsync<UnauthorizedException>(
            () => Sut.FinishLoginAsync(LoginRequest(), CancellationToken.None));

        // Same status as a failed assertion, different code: the client can offer another sign-in
        // method, and the status line still says nothing about which credential ids are real.
        ex.StatusCode.ShouldBe(401);
        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyCredentialNotFound);

        await _ceremony.DidNotReceive().CompleteLoginAsync(
            Arg.Any<WebAuthnAssertionRequest>(),
            Arg.Any<WebAuthnStoredCredential>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ACredentialBelongingToAnotherAccountCannotSatisfyAScopedCeremony()
    {
        var stored = StoredPasskey(signCount: 1);
        stored.UserId = 777;

        _ceremony
            .TakeAssertionAsync(Flow, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new WebAuthnAssertionRequest("{}", UserId, CredentialId, "{}"));
        _passkeys.FindByCredentialIdAsync(CredentialId, Arg.Any<CancellationToken>()).Returns(stored);

        var ex = await Should.ThrowAsync<UnauthorizedException>(
            () => Sut.FinishLoginAsync(LoginRequest(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyCredentialNotFound);
    }

    [Fact]
    public async Task ADisabledAccountCannotSignInWithAValidPasskey()
    {
        var stored = StoredPasskey(signCount: 0);
        GivenAssertionFor(stored);
        GivenVerifiedAssertion(signCount: 1, backupState: false);

        _users.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(new User { Id = UserId, Status = UserStatuses.Disabled });

        var ex = await Should.ThrowAsync<ForbiddenException>(
            () => Sut.FinishLoginAsync(LoginRequest(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.AccountDisabled);
        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());

        // And the row is left exactly as it was found. Refusing after the counter had already been
        // advanced in the change tracker would stage a login that never happened, waiting for the
        // next SaveChanges in the request to commit it.
        stored.SignCount.ShouldBe(0);
        stored.LastUsedAt.ShouldBeNull();
    }

    // ---------------------------------------------------------------- login begin

    [Fact]
    public async Task AnUnknownIdentifierFallsThroughToADiscoverableCeremony()
    {
        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((UserIdentity?)null);

        await Sut.BeginLoginAsync(
            new PasskeyLoginBeginRequest { Identifier = "nobody@example.com", IdentityType = "email" },
            new PasskeyRequestContext("203.0.113.7"),
            CancellationToken.None);

        // No error and no narrowed credential list: the response for an address nobody has
        // registered is indistinguishable from the response for one that is. An unauthenticated
        // endpoint that answered otherwise would be an account checker.
        await _ceremony.Received(1).BeginLoginAsync(
            Arg.Is<WebAuthnLoginTarget>(t => t.UserId == null && t.AllowCredentials.Count == 0),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AKnownIdentifierWithNoPasskeysAlsoFallsThrough()
    {
        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new UserIdentity { Id = 1, UserId = UserId, IdentityType = IdentityTypes.Email });
        _passkeys.ListByUserAsync(UserId, Arg.Any<CancellationToken>()).Returns([]);

        await Sut.BeginLoginAsync(
            new PasskeyLoginBeginRequest { Identifier = "alan@example.com", IdentityType = "email" },
            new PasskeyRequestContext("203.0.113.7"),
            CancellationToken.None);

        await _ceremony.Received(1).BeginLoginAsync(
            Arg.Is<WebAuthnLoginTarget>(t => t.UserId == null && t.AllowCredentials.Count == 0),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AKnownIdentifierWithPasskeysScopesTheCeremonyToThatAccount()
    {
        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new UserIdentity { Id = 1, UserId = UserId, IdentityType = IdentityTypes.Email });
        _passkeys.ListByUserAsync(UserId, Arg.Any<CancellationToken>())
            .Returns([StoredPasskey(signCount: 0)]);

        await Sut.BeginLoginAsync(
            new PasskeyLoginBeginRequest { Identifier = "alan@example.com", IdentityType = "email" },
            new PasskeyRequestContext("203.0.113.7"),
            CancellationToken.None);

        await _ceremony.Received(1).BeginLoginAsync(
            Arg.Is<WebAuthnLoginTarget>(t => t.UserId == UserId && t.AllowCredentials.Count == 1),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ASpentPerMinuteBudgetRefusesBeforeTheHourBudgetIsCharged()
    {
        _rateLimiter
            .TryAcquireAsync(
                Arg.Any<string>(),
                Arg.Any<string>(),
                Arg.Is<RateLimitPolicy>(p => p.Window == TimeSpan.FromMinutes(1)),
                Arg.Any<CancellationToken>())
            .Returns(new RateLimitDecision(false, 0, TimeSpan.FromSeconds(30)));

        var ex = await Should.ThrowAsync<RateLimitedException>(() => Sut.BeginLoginAsync(
            new PasskeyLoginBeginRequest(),
            new PasskeyRequestContext("203.0.113.7"),
            CancellationToken.None));

        ex.RetryAfter.ShouldBe(TimeSpan.FromSeconds(30));

        // Charging the hour window after the minute window has already refused would bill a
        // retrying client for requests nobody answered, turning a one-minute block into an hour.
        await _rateLimiter.DidNotReceive().TryAcquireAsync(
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Is<RateLimitPolicy>(p => p.Window == TimeSpan.FromHours(1)),
            Arg.Any<CancellationToken>());

        await _ceremony.DidNotReceive().BeginLoginAsync(
            Arg.Any<WebAuthnLoginTarget>(), Arg.Any<CancellationToken>());
    }

    // ---------------------------------------------------------------- registration

    [Fact]
    public async Task RegistrationExcludesTheCredentialsTheAccountAlreadyHolds()
    {
        _passkeys.ListByUserAsync(UserId, Arg.Any<CancellationToken>())
            .Returns([StoredPasskey(signCount: 0)]);

        await Sut.BeginRegistrationAsync(
            UserId, new PasskeyRegisterBeginRequest { Name = "  iPhone  " }, CancellationToken.None);

        await _ceremony.Received(1).BeginRegistrationAsync(
            Arg.Is<WebAuthnUserEntity>(u => u.UserId == UserId && u.Name == "alan"),
            Arg.Is<IReadOnlyList<WebAuthnCredentialReference>>(c => c.Count == 1),
            "iPhone",
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnAlreadyRegisteredCredentialIsAConflictNotAVerificationFailure()
    {
        GivenVerifiedRegistration();
        _passkeys.FindByCredentialIdAsync(CredentialId, Arg.Any<CancellationToken>())
            .Returns(StoredPasskey(signCount: 0));

        var ex = await Should.ThrowAsync<ConflictException>(
            () => Sut.FinishRegistrationAsync(UserId, RegisterRequest(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyAlreadyRegistered);
        ex.StatusCode.ShouldBe(409);
        _passkeys.DidNotReceive().Add(Arg.Any<UserPasskey>());
    }

    [Fact]
    public async Task AStoredCredentialCarriesTheCeremonysOwnFactsAndTheCompanionIdentityRow()
    {
        UserPasskey? added = null;
        GivenVerifiedRegistration();
        _passkeys.When(r => r.Add(Arg.Any<UserPasskey>())).Do(call =>
        {
            added = call.Arg<UserPasskey>();
            added.Id = 4711;
        });

        var response = await Sut.FinishRegistrationAsync(UserId, RegisterRequest(), CancellationToken.None);

        response.Id.ShouldBe(4711);
        response.Name.ShouldBe("Work laptop", "the finish request's label wins over the flow's");
        response.CreatedAt.ShouldBe(_clock.UtcNow);

        added.ShouldNotBeNull();
        added.CredentialId.ShouldBe(CredentialId);
        added.SignCount.ShouldBe(0);
        added.AttestationType.ShouldBe("none");
        added.BackupEligible.ShouldBeTrue();
        JsonSerializer.Deserialize<string[]>(added.Transports).ShouldBe(["internal"]);

        // The companion row is what makes the capability visible to the login-methods screen, and
        // it has to land in the same transaction as the credential.
        await _identityLink.Received(1).EnsurePasskeyIdentityAsync(UserId, Arg.Any<CancellationToken>());
        await _unitOfWork.Received(1).ExecuteInTransactionAsync(
            Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnUnlabelledRegistrationFallsBackToTheFlowLabelThenTheDefault()
    {
        UserPasskey? added = null;
        GivenVerifiedRegistration(label: null);
        _passkeys.When(r => r.Add(Arg.Any<UserPasskey>())).Do(call => added = call.Arg<UserPasskey>());

        await Sut.FinishRegistrationAsync(
            UserId,
            new PasskeyRegisterFinishRequest { FlowId = "pkreg_1", Credential = Credential() },
            CancellationToken.None);

        added!.Name.ShouldBe(UserPasskey.DefaultName);
    }

    // ---------------------------------------------------------------- management

    [Fact]
    public async Task SomebodyElsesPasskeyIsNotFoundRatherThanForbidden()
    {
        var other = StoredPasskey(signCount: 0);
        other.UserId = 999;
        _passkeys.FindByIdAsync(other.Id, Arg.Any<CancellationToken>()).Returns(other);

        var deleting = await Should.ThrowAsync<NotFoundException>(
            () => Sut.DeleteAsync(UserId, other.Id, CancellationToken.None));
        var renaming = await Should.ThrowAsync<NotFoundException>(
            () => Sut.RenameAsync(UserId, other.Id, new RenamePasskeyRequest { Name = "mine" }, CancellationToken.None));

        // 403 would be the honest status and would also confirm the id exists, which lets anyone
        // count the credentials this service holds by walking the id space.
        deleting.ErrorCode.ShouldBe(ErrorCodes.PasskeyNotFound);
        renaming.ErrorCode.ShouldBe(ErrorCodes.PasskeyNotFound);
    }

    [Fact]
    public async Task TheOnlyRemainingWayIntoAnAccountCannotBeDeleted()
    {
        var only = StoredPasskey(signCount: 0);
        _passkeys.FindByIdAsync(only.Id, Arg.Any<CancellationToken>()).Returns(only);
        _passkeys.CountByUserAsync(UserId, Arg.Any<CancellationToken>()).Returns(1);
        _identityLink.HasNonPasskeyLoginMethodAsync(UserId, Arg.Any<CancellationToken>()).Returns(false);

        var ex = await Should.ThrowAsync<ConflictException>(
            () => Sut.DeleteAsync(UserId, only.Id, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyLastLoginMethod);
        ex.StatusCode.ShouldBe(409);
        _passkeys.DidNotReceive().Remove(Arg.Any<UserPasskey>());
    }

    [Fact]
    public async Task TheLastPasskeyGoesWhenTheAccountHasAnotherWayIn()
    {
        var only = StoredPasskey(signCount: 0);
        _passkeys.FindByIdAsync(only.Id, Arg.Any<CancellationToken>()).Returns(only);
        _passkeys.CountByUserAsync(UserId, Arg.Any<CancellationToken>()).Returns(1);
        _identityLink.HasNonPasskeyLoginMethodAsync(UserId, Arg.Any<CancellationToken>()).Returns(true);

        await Sut.DeleteAsync(UserId, only.Id, CancellationToken.None);

        _passkeys.Received(1).Remove(only);

        // The companion row claims the account can sign in with a passkey; with the last one gone
        // that claim would put an option on the login screen that can never succeed.
        await _identityLink.Received(1).RetirePasskeyIdentityAsync(UserId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RemovingOneOfSeveralPasskeysLeavesTheCompanionRowAlone()
    {
        var one = StoredPasskey(signCount: 0);
        _passkeys.FindByIdAsync(one.Id, Arg.Any<CancellationToken>()).Returns(one);
        _passkeys.CountByUserAsync(UserId, Arg.Any<CancellationToken>()).Returns(3);

        await Sut.DeleteAsync(UserId, one.Id, CancellationToken.None);

        _passkeys.Received(1).Remove(one);
        await _identityLink.DidNotReceive().RetirePasskeyIdentityAsync(
            Arg.Any<int>(), Arg.Any<CancellationToken>());

        // Not even asked: the account still has passkeys, so no lockout is possible.
        await _identityLink.DidNotReceive().HasNonPasskeyLoginMethodAsync(
            Arg.Any<int>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnAccountWithNoPasskeysListsAnEmptyCollection()
    {
        _passkeys.ListByUserAsync(UserId, Arg.Any<CancellationToken>()).Returns([]);

        var response = await Sut.ListAsync(UserId, CancellationToken.None);

        response.Passkeys.ShouldBeEmpty();
    }

    [Fact]
    public async Task ListingReportsTheLabelAndTheNeverUsedCase()
    {
        var used = StoredPasskey(signCount: 3);
        used.Id = 1;
        used.Name = "iPhone";
        used.LastUsedAt = _clock.UtcNow;

        var unused = StoredPasskey(signCount: 0);
        unused.Id = 2;
        unused.Name = null;

        _passkeys.ListByUserAsync(UserId, Arg.Any<CancellationToken>()).Returns([used, unused]);

        var response = await Sut.ListAsync(UserId, CancellationToken.None);

        response.Passkeys[0].Name.ShouldBe("iPhone");
        response.Passkeys[0].LastUsedAt.ShouldBe(_clock.UtcNow);
        response.Passkeys[1].Name.ShouldBe(UserPasskey.DefaultName, "a label-less legacy row still needs a name to render");
        response.Passkeys[1].LastUsedAt.ShouldBeNull();
    }

    [Fact]
    public async Task RenamingWritesTheTrimmedLabel()
    {
        var passkey = StoredPasskey(signCount: 0);
        _passkeys.FindByIdAsync(passkey.Id, Arg.Any<CancellationToken>()).Returns(passkey);

        var response = await Sut.RenameAsync(
            UserId, passkey.Id, new RenamePasskeyRequest { Name = "  Work laptop " }, CancellationToken.None);

        response.Name.ShouldBe("Work laptop");
        passkey.UpdatedAt.ShouldBe(_clock.UtcNow);
        await _unitOfWork.Received(1).SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    private static UserPasskey StoredPasskey(long signCount) => new()
    {
        Id = 7,
        UserId = UserId,
        CredentialId = CredentialId,
        PublicKey = [9, 9],
        SignCount = signCount,
        Transports = """["internal"]""",
        Name = "iPhone",
        CreatedAt = new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero),
    };

    private static PasskeyLoginFinishRequest LoginRequest() =>
        new() { FlowId = Flow, Credential = Credential() };

    private static PasskeyRegisterFinishRequest RegisterRequest() =>
        new() { FlowId = "pkreg_1", Name = "Work laptop", Credential = Credential() };

    private static JsonElement Credential() =>
        JsonDocument.Parse("""{"id":"AQIDBA"}""").RootElement;

    private void GivenAssertionFor(UserPasskey stored)
    {
        _ceremony
            .TakeAssertionAsync(Flow, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new WebAuthnAssertionRequest("{}", null, stored.CredentialId, "{}"));

        _passkeys.FindByCredentialIdAsync(stored.CredentialId, Arg.Any<CancellationToken>()).Returns(stored);
    }

    private void GivenVerifiedAssertion(long signCount, bool backupState) =>
        _ceremony
            .CompleteLoginAsync(
                Arg.Any<WebAuthnAssertionRequest>(),
                Arg.Any<WebAuthnStoredCredential>(),
                Arg.Any<CancellationToken>())
            .Returns(new WebAuthnAssertion(CredentialId, signCount, backupState));

    private void GivenVerifiedRegistration(string? label = "flow label") =>
        _ceremony
            .CompleteRegistrationAsync(
                Arg.Any<string>(), UserId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new WebAuthnRegistration(
                CredentialId,
                [8, 8],
                0,
                null,
                ["internal"],
                "none",
                BackupEligible: true,
                BackupState: false,
                label));
}
