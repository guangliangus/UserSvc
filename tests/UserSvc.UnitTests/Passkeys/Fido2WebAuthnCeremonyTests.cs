using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Auth;
using UserSvc.Infrastructure.Auth;
using Xunit;

namespace UserSvc.UnitTests.Passkeys;

/// <summary>
/// The WebAuthn adapter against a real software authenticator: real key pairs, real signatures,
/// real CBOR. Only the ceremony store is substituted, so everything these tests exercise below that
/// seam is the code that runs in production.
/// <para>
/// <b>The clone tests are the reason this file exists.</b> A passkey's advantage over a password is
/// that the private key cannot be copied off the authenticator; the signature counter is the only
/// evidence available when it has been. Four cases have to hold together, and getting any one of
/// them wrong is either a lockout or a silent hole: a counter that advances is fine, a counter that
/// repeats is a clone, a counter that goes backwards is a clone, and a counter that is always zero
/// is a large and entirely legitimate share of the world's authenticators.
/// </para>
/// </summary>
public sealed class Fido2WebAuthnCeremonyTests
{
    private const string Origin = "https://liontrip.com";
    private const int UserId = 42;

    private readonly InMemoryPasskeyFlowStore _flows = new();

    private Fido2WebAuthnCeremony Sut => new(
        _flows,
        Options.Create(new PasskeyOptions
        {
            RpId = "liontrip.com",
            RpDisplayName = "LionTrip",
            Origins = [Origin],
        }),
        NullLogger<Fido2WebAuthnCeremony>.Instance);

    [Fact]
    public async Task ARegistrationRoundTripYieldsAStorableCredential()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator();

        var start = await sut.BeginRegistrationAsync(User(), [], "iPhone", CancellationToken.None);
        var registration = await CompleteRegistrationAsync(sut, start, authenticator);

        registration.CredentialId.ShouldBe(authenticator.CredentialId);
        registration.PublicKey.ShouldNotBeEmpty();
        registration.AttestationFormat.ShouldBe("none");
        registration.Transports.ShouldBe(["internal"]);
        registration.BackupEligible.ShouldBeTrue();
        registration.BackupState.ShouldBeTrue();
        registration.Aaguid!.Length.ShouldBe(16);

        // The label given at begin time survives to finish time, which is what lets a client name
        // the key before the user has been asked to create it.
        registration.Label.ShouldBe("iPhone");
    }

    [Fact]
    public async Task AnAuthenticatorThatDeclinesToIdentifyItselfStoresNoAaguid()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator { Aaguid = Guid.Empty };

        var start = await sut.BeginRegistrationAsync(User(), [], null, CancellationToken.None);
        var registration = await CompleteRegistrationAsync(sut, start, authenticator);

        // Null rather than sixteen zero bytes: "did not say" is one value, not two.
        registration.Aaguid.ShouldBeNull();
    }

    [Fact]
    public async Task AChallengeIsSpentByTheFirstAttemptToUseIt()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator();

        var start = await sut.BeginRegistrationAsync(User(), [], null, CancellationToken.None);
        await CompleteRegistrationAsync(sut, start, authenticator);

        _flows.Count.ShouldBe(0, "a consumed ceremony must leave nothing behind to replay");

        var replay = await Should.ThrowAsync<BadRequestException>(
            () => CompleteRegistrationAsync(sut, start, authenticator));

        replay.ErrorCode.ShouldBe(ErrorCodes.PasskeyFlowExpired);
        replay.StatusCode.ShouldBe(400);
    }

    [Fact]
    public async Task AChallengeIssuedForOneAccountCannotBeFinishedByAnother()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator();

        var start = await sut.BeginRegistrationAsync(User(), [], null, CancellationToken.None);
        var attestation = authenticator.CreateAttestation(start.OptionsJson, Origin);

        var ex = await Should.ThrowAsync<BadRequestException>(() => sut.CompleteRegistrationAsync(
            start.FlowId, UserId + 1, attestation, CancellationToken.None));

        // The same answer an unknown flow id gets, on purpose: a distinct one would confirm the
        // flow exists and belongs to somebody.
        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyFlowExpired);
    }

    [Fact]
    public async Task ARegistrationChallengeCannotBeSpentAsALogin()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator();

        var start = await sut.BeginRegistrationAsync(User(), [], null, CancellationToken.None);

        var ex = await Should.ThrowAsync<BadRequestException>(() => sut.TakeAssertionAsync(
            start.FlowId,
            authenticator.CreateAssertion(start.OptionsJson, Origin, 1, UserId),
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyFlowExpired);
    }

    [Fact]
    public async Task AnOriginThatIsNotOnTheListIsRefused()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator();

        var start = await sut.BeginRegistrationAsync(User(), [], null, CancellationToken.None);
        var attestation = authenticator.CreateAttestation(start.OptionsJson, "https://liontrip.com.evil.example");

        var ex = await Should.ThrowAsync<BadRequestException>(() => sut.CompleteRegistrationAsync(
            start.FlowId, UserId, attestation, CancellationToken.None));

        // This single check is the phishing resistance: the signature is perfectly valid, and the
        // only thing wrong with it is where it was produced.
        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyVerificationFailed);
    }

    [Fact]
    public async Task ACredentialThatIsNotJsonIsRefusedBeforeAnyVerification()
    {
        var sut = Sut;
        var start = await sut.BeginRegistrationAsync(User(), [], null, CancellationToken.None);

        var ex = await Should.ThrowAsync<BadRequestException>(() => sut.CompleteRegistrationAsync(
            start.FlowId, UserId, "this is not a credential", CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyInvalidRequest);
    }

    [Fact]
    public async Task AnAssertionThatNamesNoCredentialIsRefused()
    {
        var sut = Sut;
        var start = await sut.BeginLoginAsync(new WebAuthnLoginTarget(null, []), CancellationToken.None);

        var ex = await Should.ThrowAsync<BadRequestException>(() => sut.TakeAssertionAsync(
            start.FlowId, "{}", CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyInvalidRequest);
    }

    [Fact]
    public async Task ALoginRoundTripVerifiesAndReportsTheNewCounter()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator();
        var stored = await RegisterAsync(sut, authenticator);

        var assertion = await AssertAsync(sut, authenticator, stored, presentedSignCount: 5);

        assertion.CredentialId.ShouldBe(authenticator.CredentialId);
        assertion.SignCount.ShouldBe(5);
        assertion.BackupState.ShouldBeTrue();
    }

    [Fact]
    public async Task ADiscoverableLoginOffersNoCredentialList()
    {
        var sut = Sut;
        var start = await sut.BeginLoginAsync(new WebAuthnLoginTarget(null, []), CancellationToken.None);

        // An anonymous caller must not be handed the credential ids of an account they have not
        // authenticated as - which is exactly what a populated allowCredentials would be. The
        // member is present and empty, which is how WebAuthn spells "let the authenticator choose".
        Fido2NetLib.AssertionOptions.FromJson(start.OptionsJson).AllowCredentials.ShouldBeEmpty();
        start.OptionsJson.ShouldContain("challenge");
    }

    [Fact]
    public async Task ARepeatedSignatureCounterIsReportedAsAPossibleClone()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator();
        var stored = await RegisterAsync(sut, authenticator);

        // The genuine authenticator has already reached 5. A clone of it, restored from a backup of
        // the key, presents the same counter it last saw - which a counting authenticator never
        // does, because it increments before it signs.
        var ex = await Should.ThrowAsync<UnauthorizedException>(
            () => AssertAsync(sut, authenticator, stored with { SignCount = 5 }, presentedSignCount: 5));

        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyPossibleClone);
        ex.StatusCode.ShouldBe(401);
    }

    [Fact]
    public async Task ASignatureCounterThatWentBackwardsIsReportedAsAPossibleClone()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator();
        var stored = await RegisterAsync(sut, authenticator);

        var ex = await Should.ThrowAsync<UnauthorizedException>(
            () => AssertAsync(sut, authenticator, stored with { SignCount = 5 }, presentedSignCount: 3));

        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyPossibleClone);
    }

    [Fact]
    public async Task AnAuthenticatorThatAlwaysReportsZeroSignsInRepeatedly()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator();
        var stored = await RegisterAsync(sut, authenticator);

        // Apple's and most Android platform authenticators behave exactly like this: the counter is
        // a cross-site correlation handle, so they refuse to keep one. Reading a constant zero as a
        // clone would lock every one of those users out on their second sign-in.
        var first = await AssertAsync(sut, authenticator, stored, presentedSignCount: 0);
        var second = await AssertAsync(sut, authenticator, stored, presentedSignCount: 0);

        first.SignCount.ShouldBe(0);
        second.SignCount.ShouldBe(0);
    }

    [Fact]
    public async Task AnAssertionThatDoesNotVerifyIsNotReportedAsAClone()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator();
        var stored = await RegisterAsync(sut, authenticator);

        var start = await sut.BeginLoginAsync(new WebAuthnLoginTarget(null, []), CancellationToken.None);
        var assertion = authenticator.CreateAssertion(start.OptionsJson, Origin, 7, UserId, tamperWithSignature: true);
        var request = await sut.TakeAssertionAsync(start.FlowId, assertion, CancellationToken.None);

        var ex = await Should.ThrowAsync<UnauthorizedException>(
            () => sut.CompleteLoginAsync(request, stored, CancellationToken.None));

        // Both are 401, and the codes differ. A client shows the same screen for either; an
        // operator alerts on only one of them, which is only possible because they are distinct.
        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyVerificationFailed);
    }

    [Fact]
    public async Task AnAssertionCarryingAnotherAccountsUserHandleIsRefused()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator();
        var stored = await RegisterAsync(sut, authenticator);

        var start = await sut.BeginLoginAsync(new WebAuthnLoginTarget(null, []), CancellationToken.None);

        // The signature is genuine and the credential id is ours; only the account handle is
        // somebody else's. Without the ownership callback this would sign the wrong person in.
        var assertion = authenticator.CreateAssertion(start.OptionsJson, Origin, 1, userId: 9999);
        var request = await sut.TakeAssertionAsync(start.FlowId, assertion, CancellationToken.None);

        var ex = await Should.ThrowAsync<UnauthorizedException>(
            () => sut.CompleteLoginAsync(request, stored, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.PasskeyVerificationFailed);
    }

    [Fact]
    public async Task AnIdentifierScopedLoginRemembersWhichAccountItWasBegunFor()
    {
        var sut = Sut;
        using var authenticator = new VirtualAuthenticator();

        var start = await sut.BeginLoginAsync(
            new WebAuthnLoginTarget(UserId, [new WebAuthnCredentialReference(authenticator.CredentialId, ["internal"])]),
            CancellationToken.None);

        var request = await sut.TakeAssertionAsync(
            start.FlowId,
            authenticator.CreateAssertion(start.OptionsJson, Origin, 1, UserId),
            CancellationToken.None);

        // The application service compares this against the credential's owner; the ceremony's job
        // is only to carry it across the two requests intact.
        request.UserId.ShouldBe(UserId);
        request.CredentialId.ShouldBe(authenticator.CredentialId);
    }

    private static WebAuthnUserEntity User() => new(UserId, "user-42", "user-42");

    private static async Task<WebAuthnRegistration> CompleteRegistrationAsync(
        Fido2WebAuthnCeremony sut,
        WebAuthnCeremonyStart start,
        VirtualAuthenticator authenticator) =>
        await sut.CompleteRegistrationAsync(
            start.FlowId,
            UserId,
            authenticator.CreateAttestation(start.OptionsJson, Origin),
            CancellationToken.None);

    /// <summary>Enrols the authenticator and returns what the database would then hold for it.</summary>
    private async Task<WebAuthnStoredCredential> RegisterAsync(
        Fido2WebAuthnCeremony sut,
        VirtualAuthenticator authenticator)
    {
        var start = await sut.BeginRegistrationAsync(User(), [], null, CancellationToken.None);
        var registration = await CompleteRegistrationAsync(sut, start, authenticator);

        return new WebAuthnStoredCredential(
            registration.CredentialId,
            registration.PublicKey,
            registration.SignCount,
            UserId);
    }

    private async Task<WebAuthnAssertion> AssertAsync(
        Fido2WebAuthnCeremony sut,
        VirtualAuthenticator authenticator,
        WebAuthnStoredCredential stored,
        uint presentedSignCount)
    {
        var start = await sut.BeginLoginAsync(new WebAuthnLoginTarget(null, []), CancellationToken.None);
        var assertion = authenticator.CreateAssertion(start.OptionsJson, Origin, presentedSignCount, UserId);
        var request = await sut.TakeAssertionAsync(start.FlowId, assertion, CancellationToken.None);

        return await sut.CompleteLoginAsync(request, stored, CancellationToken.None);
    }
}
