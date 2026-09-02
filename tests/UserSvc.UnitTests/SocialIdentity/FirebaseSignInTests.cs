using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Application.Ports.External;
using UserSvc.Domain.Users;
using Xunit;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// Firebase sign-in, the consent flow, and binding. The verifier is substituted - a real one needs
/// Google's public keys - and everything downstream of it is exercised for real.
/// </summary>
public sealed class FirebaseSignInTests
{
    private const string Uid = "firebase-uid-1";
    private const string ProviderUid = "google-sub-1";
    private const string Google = "google.com";
    private const string Apple = "apple.com";
    private const string Email = "carol@gmail.com";

    private readonly SocialIdentityFixture _fixture = new();

    private SocialIdentityAppService Sut => _fixture.Sut;

    private static FirebaseSignInRequest Request(string provider = Google) =>
        new() { FirebaseIdToken = "header.payload.signature", Provider = provider };

    private void GivenFirebaseVerifies(
        string uid = Uid,
        string provider = Google,
        string providerUid = ProviderUid,
        string email = "",
        bool emailVerified = true,
        string name = "Carol",
        string picture = "https://firebase/pic.png") =>
        _fixture.Firebase.VerifyIdTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new FirebaseIdentity(uid, provider, providerUid, email, emailVerified, name, picture));

    // ------------------------------------------------------------------ provider allow-list

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task AMissingProviderIsRefusedBeforeTheTokenIsVerified(string provider)
    {
        var thrown = await Should.ThrowAsync<BadRequestException>(() =>
            Sut.SignInWithFirebaseAsync(Request(provider), CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.FirebaseProviderRequired);
        await _fixture.Firebase.DidNotReceiveWithAnyArgs().VerifyIdTokenAsync(default!, default);
    }

    /// <summary>
    /// An allow-list rather than a block-list, because Firebase mints tokens for anything enabled
    /// in its console - anonymous and custom-token sign-ins included, which prove nothing about who
    /// is holding the phone.
    /// </summary>
    [Fact]
    public async Task AProviderNobodyEnabledCannotOpenAnAccount()
    {
        var thrown = await Should.ThrowAsync<BadRequestException>(() =>
            Sut.SignInWithFirebaseAsync(Request("facebook.com"), CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.FirebaseProviderNotAllowed);
        await _fixture.Firebase.DidNotReceiveWithAnyArgs().VerifyIdTokenAsync(default!, default);
    }

    /// <summary>
    /// The token's own claim is authoritative and the client's field is not. A client that could
    /// steer which provider a token is filed under could file an Apple token as a Google one and
    /// land on the wrong identity row.
    /// </summary>
    [Fact]
    public async Task ATokenFromADifferentProviderThanClaimedIsRefused()
    {
        GivenFirebaseVerifies(provider: Apple);

        var thrown = await Should.ThrowAsync<UnauthorizedException>(() =>
            Sut.SignInWithFirebaseAsync(Request(Google), CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.FirebaseProviderMismatch);

        // The actual provider is named, because the caller is holding the token it came from.
        thrown.Message.ShouldContain(Apple);
    }

    // ------------------------------------------------------------------ new accounts

    [Fact]
    public async Task AFirstFirebaseSignInWithNoEmailCreatesOneIdentity()
    {
        GivenFirebaseVerifies();

        var response = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        response.NeedsBindingConsent.ShouldBeFalse();
        response.FirebaseUid.ShouldBe(Uid);
        response.Provider.ShouldBe(Google);
        response.ProviderUid.ShouldBe(ProviderUid);

        var account = response.Account.ShouldNotBeNull();
        account.IsNewUser.ShouldBeTrue();

        var identity = _fixture.Store.Identities.ShouldHaveSingleItem();
        identity.IdentityType.ShouldBe(IdentityTypes.Firebase);
        identity.Provider.ShouldBe(Google);
        identity.ProviderUid.ShouldBe(ProviderUid);
        identity.IdentifierHash.ShouldBe(_fixture.HashOfSubject(Uid));
    }

    [Fact]
    public async Task AFirstFirebaseSignInWithAnUnclaimedEmailBindsItToo()
    {
        GivenFirebaseVerifies(email: Email);

        await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        _fixture.Store.Identities.Select(i => i.IdentityType)
            .ShouldBe([IdentityTypes.Firebase, IdentityTypes.Email], ignoreOrder: true);

        var firebase = _fixture.Store.Identities.Single(i => i.IdentityType == IdentityTypes.Firebase);
        firebase.ProviderDetails.ShouldContain("car***@gmail.com");
        firebase.ProviderDetails.ShouldContain("Carol");

        _fixture.Store.Users.ShouldHaveSingleItem().Nickname.ShouldBe("Carol");
    }

    /// <summary>
    /// <b>An unverified address is still matched and still bound.</b> That reads like a bug and is
    /// the original's behaviour: several providers leave <c>email_verified</c> false on addresses
    /// they are perfectly certain about, and requiring the claim would push those users into
    /// creating a duplicate account beside the one they already have.
    /// </summary>
    [Fact]
    public async Task AnUnverifiedEmailIsStillBound()
    {
        GivenFirebaseVerifies(email: "unverified@example.com", emailVerified: false);

        await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        _fixture.Store.Identities.Count(i => i.IdentityType == IdentityTypes.Email).ShouldBe(1);
    }

    /// <summary>
    /// An Apple private-relay address is a per-app proxy: it can never match another account and
    /// the user can never sign in elsewhere with it. Persisting one would create a login identifier
    /// nobody can type.
    /// </summary>
    [Fact]
    public async Task AnApplePrivateRelayAddressIsNeitherMatchedNorPersisted()
    {
        var owner = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(
            owner.Id, IdentityTypes.Email, _fixture.HashOfEmail("abc123@privaterelay.appleid.com"));

        GivenFirebaseVerifies(provider: Apple, email: "abc123@PrivateRelay.AppleID.com");

        var response = await Sut.SignInWithFirebaseAsync(Request(Apple), CancellationToken.None);

        // No consent request, no merge into the account that owns the relay address, and no second
        // email identity: a brand-new account with exactly one identity.
        response.NeedsBindingConsent.ShouldBeFalse();
        response.Account.ShouldNotBeNull().IsNewUser.ShouldBeTrue();
        _fixture.Store.Identities.Count(i => i.IdentityType == IdentityTypes.Email).ShouldBe(1);
        _fixture.Store.Identities.Count(i => i.IdentityType == IdentityTypes.Firebase).ShouldBe(1);
    }

    // ------------------------------------------------------------------ returning users

    [Fact]
    public async Task AReturningUserResolvesOnTheUidAndNeverLooksAtTheEmail()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(
            user.Id, IdentityTypes.Firebase, _fixture.HashOfSubject(Uid), Google, ProviderUid);

        GivenFirebaseVerifies(email: Email);

        var response = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        response.Account.ShouldNotBeNull().UserId.ShouldBe(user.Id);
        response.Account.IsNewUser.ShouldBeFalse();

        // A second sign-in must never re-ask for consent, which is what skipping the email lookup
        // guarantees.
        _fixture.Store.Reads.ShouldNotContain(r => r.IdentityType == IdentityTypes.Email);
    }

    /// <summary>
    /// Firebase mints a new uid when its user record is deleted and re-created for the same Google
    /// account. Without the provider-key fallback, that user is funnelled through the consent flow
    /// on every single login.
    /// </summary>
    [Fact]
    public async Task AStaleUidStillResolvesThroughTheProviderKey()
    {
        var user = _fixture.Store.GivenUser();
        var identity = _fixture.Store.GivenIdentity(
            user.Id, IdentityTypes.Firebase, _fixture.HashOfSubject("firebase-uid-OLD"), Google, ProviderUid);

        GivenFirebaseVerifies(email: Email);

        var response = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        response.Account.ShouldNotBeNull().UserId.ShouldBe(user.Id);
        response.Account.IsNewUser.ShouldBeFalse();
        _fixture.Store.Reads.ShouldNotContain(r => r.IdentityType == IdentityTypes.Email);

        // Self-healed, so the next sign-in takes the fast path again.
        identity.IdentifierHash.ShouldBe(_fixture.HashOfSubject(Uid));
        identity.IdentifierCiphertext.ShouldNotBeEmpty();
        identity.IdentifierKeyVersion.ShouldBe("test");
        _fixture.Store.Updated.ShouldContain(identity);
    }

    /// <summary>
    /// The fallback is keyed on (provider, subject), so it must not reach across providers: an
    /// Apple identity holding the same subject string is a different account.
    /// </summary>
    [Fact]
    public async Task TheProviderKeyFallbackDoesNotReachAcrossProviders()
    {
        var other = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(
            other.Id, IdentityTypes.Firebase, _fixture.HashOfSubject("uid-x"), Apple, ProviderUid);

        GivenFirebaseVerifies();

        var response = await Sut.SignInWithFirebaseAsync(Request(Google), CancellationToken.None);

        response.Account.ShouldNotBeNull().IsNewUser.ShouldBeTrue();
        response.Account.UserId.ShouldNotBe(other.Id);
    }

    [Fact]
    public async Task ANonActiveAccountReportsNotActivated()
    {
        var user = _fixture.Store.GivenUser(UserStatuses.Disabled);
        _fixture.Store.GivenIdentity(
            user.Id, IdentityTypes.Firebase, _fixture.HashOfSubject(Uid), Google, ProviderUid);

        GivenFirebaseVerifies();

        var thrown = await Should.ThrowAsync<ForbiddenException>(() =>
            Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.AccountNotActivated);
    }

    [Fact]
    public async Task FirebaseSignInAdvancesLastLogin()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(
            user.Id, IdentityTypes.Firebase, _fixture.HashOfSubject(Uid), Google, ProviderUid);

        GivenFirebaseVerifies();

        await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        user.LastLoginAt.ShouldBe(_fixture.Clock.UtcNow);
    }

    // ------------------------------------------------------------------ the consent flow

    /// <summary>
    /// The address belongs to somebody here. Nothing is created and nothing is linked - the human
    /// decides. Compare the LINE path, which merges silently on the same signal.
    /// </summary>
    [Fact]
    public async Task AnOccupiedEmailAddressAsksForConsentAndWritesNothing()
    {
        var owner = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(owner.Id, IdentityTypes.Email, _fixture.HashOfEmail(Email));

        GivenFirebaseVerifies(email: Email);

        var response = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        response.NeedsBindingConsent.ShouldBeTrue();
        response.Account.ShouldBeNull();
        response.BindingToken.ShouldNotBeNullOrEmpty();

        // Masked, because at this point the caller has proved control of a Firebase account and
        // nothing more - the account being offered may be somebody else's.
        response.ExistingUserMaskedEmail.ShouldBe("car***@gmail.com");

        _fixture.Store.Users.Count.ShouldBe(1);
        _fixture.Store.Identities.Count.ShouldBe(1);
        _fixture.Store.SaveCount.ShouldBe(0);
    }

    [Fact]
    public async Task ConfirmingTheProposalAttachesTheIdentityToTheAccountInsideTheToken()
    {
        var owner = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(owner.Id, IdentityTypes.Email, _fixture.HashOfEmail(Email));
        GivenFirebaseVerifies(email: Email);

        var proposal = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        var confirmed = await Sut.ConfirmFirebaseBindingAsync(
            new ConfirmFirebaseBindingRequest { BindingToken = proposal.BindingToken!, Confirm = true },
            CancellationToken.None);

        confirmed.Status.ShouldBe(FirebaseBindingStatuses.Confirmed);
        confirmed.Account.ShouldNotBeNull().UserId.ShouldBe(owner.Id);

        var firebase = _fixture.Store.Identities.Single(i => i.IdentityType == IdentityTypes.Firebase);
        firebase.UserId.ShouldBe(owner.Id);
        firebase.Provider.ShouldBe(Google);
        firebase.ProviderUid.ShouldBe(ProviderUid);
        firebase.ProviderDetails.ShouldContain("car***@gmail.com");
        firebase.ProviderDetails.ShouldContain("Carol");
        owner.LastLoginAt.ShouldBe(_fixture.Clock.UtcNow);
    }

    /// <summary>Declining reads nothing and writes nothing - not even a lookup of the target.</summary>
    [Fact]
    public async Task DecliningTheProposalTouchesNothing()
    {
        var owner = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(owner.Id, IdentityTypes.Email, _fixture.HashOfEmail(Email));
        GivenFirebaseVerifies(email: Email);

        var proposal = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        var declined = await Sut.ConfirmFirebaseBindingAsync(
            new ConfirmFirebaseBindingRequest { BindingToken = proposal.BindingToken!, Confirm = false },
            CancellationToken.None);

        declined.Status.ShouldBe(FirebaseBindingStatuses.Canceled);
        declined.Account.ShouldBeNull();
        _fixture.Store.Identities.Count.ShouldBe(1);
        _fixture.Store.SaveCount.ShouldBe(0);
    }

    [Fact]
    public async Task ConfirmingTwiceIsIdempotent()
    {
        var owner = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(owner.Id, IdentityTypes.Email, _fixture.HashOfEmail(Email));
        GivenFirebaseVerifies(email: Email);

        var proposal = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);
        var request = new ConfirmFirebaseBindingRequest { BindingToken = proposal.BindingToken!, Confirm = true };

        await Sut.ConfirmFirebaseBindingAsync(request, CancellationToken.None);
        var second = await Sut.ConfirmFirebaseBindingAsync(request, CancellationToken.None);

        second.Status.ShouldBe(FirebaseBindingStatuses.Confirmed);
        _fixture.Store.Identities.Count(i => i.IdentityType == IdentityTypes.Firebase).ShouldBe(1);
    }

    [Fact]
    public async Task ConfirmingAProposalWhoseIdentityBelongsToAnotherAccountIsAConflict()
    {
        var owner = _fixture.Store.GivenUser();
        var other = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(owner.Id, IdentityTypes.Email, _fixture.HashOfEmail(Email));
        GivenFirebaseVerifies(email: Email);

        var proposal = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        _fixture.Store.GivenIdentity(
            other.Id, IdentityTypes.Firebase, _fixture.HashOfSubject(Uid), Google, ProviderUid);

        var thrown = await Should.ThrowAsync<ConflictException>(() =>
            Sut.ConfirmFirebaseBindingAsync(
                new ConfirmFirebaseBindingRequest { BindingToken = proposal.BindingToken!, Confirm = true },
                CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.FirebaseIdentityAlreadyBound);
    }

    /// <summary>
    /// The second precheck earns its keep here: the row is the same person's under an older uid, so
    /// the uid lookup misses it and the insert would collide with the unique index.
    /// </summary>
    [Fact]
    public async Task ConfirmingWhenTheProviderKeyIsAlreadyOnTheTargetSelfHealsInsteadOfInserting()
    {
        var owner = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(owner.Id, IdentityTypes.Email, _fixture.HashOfEmail(Email));
        GivenFirebaseVerifies(email: Email);

        var proposal = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        var stale = _fixture.Store.GivenIdentity(
            owner.Id, IdentityTypes.Firebase, _fixture.HashOfSubject("firebase-uid-OLD"), Google, ProviderUid);

        var confirmed = await Sut.ConfirmFirebaseBindingAsync(
            new ConfirmFirebaseBindingRequest { BindingToken = proposal.BindingToken!, Confirm = true },
            CancellationToken.None);

        confirmed.Status.ShouldBe(FirebaseBindingStatuses.Confirmed);
        _fixture.Store.Identities.Count(i => i.IdentityType == IdentityTypes.Firebase).ShouldBe(1);
        stale.IdentifierHash.ShouldBe(_fixture.HashOfSubject(Uid));
    }

    /// <summary>
    /// Two confirmations racing: both pass the prechecks, one wins the insert, and the loser must
    /// be folded back into the same idempotent answer rather than shown a raw constraint violation
    /// for an operation that did in fact happen.
    /// </summary>
    [Fact]
    public async Task LosingTheConfirmInsertRaceResolvesAgainstTheWinner()
    {
        var owner = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(owner.Id, IdentityTypes.Email, _fixture.HashOfEmail(Email));
        GivenFirebaseVerifies(email: Email);

        var proposal = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        // The winner commits between our prechecks and our insert.
        _fixture.Store.BeforeNextSave = () => _fixture.Store.GivenIdentity(
            owner.Id, IdentityTypes.Firebase, _fixture.HashOfSubject(Uid), Google, ProviderUid);

        var confirmed = await Sut.ConfirmFirebaseBindingAsync(
            new ConfirmFirebaseBindingRequest { BindingToken = proposal.BindingToken!, Confirm = true },
            CancellationToken.None);

        confirmed.Status.ShouldBe(FirebaseBindingStatuses.Confirmed);
        _fixture.Store.Identities.Count(i => i.IdentityType == IdentityTypes.Firebase).ShouldBe(1);
    }

    [Fact]
    public async Task LosingTheRaceToAnotherAccountIsAConflictRatherThanASuccess()
    {
        var owner = _fixture.Store.GivenUser();
        var other = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(owner.Id, IdentityTypes.Email, _fixture.HashOfEmail(Email));
        GivenFirebaseVerifies(email: Email);

        var proposal = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        _fixture.Store.BeforeNextSave = () => _fixture.Store.GivenIdentity(
            other.Id, IdentityTypes.Firebase, _fixture.HashOfSubject(Uid), Google, ProviderUid);

        var thrown = await Should.ThrowAsync<ConflictException>(() =>
            Sut.ConfirmFirebaseBindingAsync(
                new ConfirmFirebaseBindingRequest { BindingToken = proposal.BindingToken!, Confirm = true },
                CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.FirebaseIdentityAlreadyBound);
    }

    [Fact]
    public async Task AForgedProposalIsRefused()
    {
        var thrown = await Should.ThrowAsync<UnauthorizedException>(() =>
            Sut.ConfirmFirebaseBindingAsync(
                new ConfirmFirebaseBindingRequest { BindingToken = "not-a-token", Confirm = true },
                CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.BindingTokenInvalid);
    }

    /// <summary>
    /// The target comes out of the signature, never from the request. Without that, a client could
    /// swap the account between the proposal and the confirmation - which is the attack a "pass the
    /// user id back" design invites.
    /// </summary>
    [Fact]
    public async Task TheTargetAccountComesFromTheSignedProposalOnly()
    {
        var owner = _fixture.Store.GivenUser();
        var victim = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(owner.Id, IdentityTypes.Email, _fixture.HashOfEmail(Email));
        GivenFirebaseVerifies(email: Email);

        var proposal = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        var confirmed = await Sut.ConfirmFirebaseBindingAsync(
            new ConfirmFirebaseBindingRequest { BindingToken = proposal.BindingToken!, Confirm = true },
            CancellationToken.None);

        confirmed.Account.ShouldNotBeNull().UserId.ShouldBe(owner.Id);
        _fixture.Store.Identities.ShouldNotContain(i => i.UserId == victim.Id);
    }

    [Fact]
    public async Task ConfirmingIntoANonActiveAccountIsRefused()
    {
        var owner = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(owner.Id, IdentityTypes.Email, _fixture.HashOfEmail(Email));
        GivenFirebaseVerifies(email: Email);

        var proposal = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);
        owner.Status = UserStatuses.Disabled;

        var thrown = await Should.ThrowAsync<ForbiddenException>(() =>
            Sut.ConfirmFirebaseBindingAsync(
                new ConfirmFirebaseBindingRequest { BindingToken = proposal.BindingToken!, Confirm = true },
                CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.AccountNotActivated);
        _fixture.Store.Identities.Count.ShouldBe(1);
    }

    // ------------------------------------------------------------------ binding

    /// <summary>No consent screen on this path: the caller holds a session on the target account.</summary>
    [Fact]
    public async Task BindingAttachesTheFirebaseIdentityToTheCallersAccount()
    {
        var user = _fixture.Store.GivenUser();
        GivenFirebaseVerifies(provider: Apple, email: Email, name: "Apple User");

        await Sut.BindFirebaseAsync(user.Id, Request(Apple), CancellationToken.None);

        var identity = _fixture.Store.Identities.ShouldHaveSingleItem();
        identity.UserId.ShouldBe(user.Id);
        identity.Provider.ShouldBe(Apple);
        identity.ProviderDetails.ShouldContain("car***@gmail.com");
        identity.ProviderDetails.ShouldContain("Apple User");
    }

    /// <summary>
    /// An Apple relay address must not even be recorded in its masked form: what is masked here is
    /// meant to help a human recognise their account, and a per-app proxy helps nobody.
    /// </summary>
    [Fact]
    public async Task BindingDoesNotRecordAnApplePrivateRelayAddress()
    {
        var user = _fixture.Store.GivenUser();
        GivenFirebaseVerifies(provider: Apple, email: "abc@privaterelay.appleid.com", name: "Apple User");

        await Sut.BindFirebaseAsync(user.Id, Request(Apple), CancellationToken.None);

        _fixture.Store.Identities.ShouldHaveSingleItem().ProviderDetails.ShouldNotContain("privaterelay");
    }

    [Fact]
    public async Task BindingAnIdentityTheCallerAlreadyOwnsChangesNothing()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(
            user.Id, IdentityTypes.Firebase, _fixture.HashOfSubject(Uid), Google, ProviderUid);

        GivenFirebaseVerifies();

        await Sut.BindFirebaseAsync(user.Id, Request(), CancellationToken.None);

        _fixture.Store.Identities.Count.ShouldBe(1);
        _fixture.Store.SaveCount.ShouldBe(0);
    }

    [Fact]
    public async Task BindingAnIdentityOwnedByAnotherAccountIsAConflict()
    {
        var caller = _fixture.Store.GivenUser();
        var other = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(
            other.Id, IdentityTypes.Firebase, _fixture.HashOfSubject(Uid), Google, ProviderUid);

        GivenFirebaseVerifies();

        var thrown = await Should.ThrowAsync<ConflictException>(() =>
            Sut.BindFirebaseAsync(caller.Id, Request(), CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.FirebaseIdentityAlreadyBound);
    }

    [Fact]
    public async Task BindingASameAccountUnderAStaleUidSelfHealsInsteadOfInserting()
    {
        var user = _fixture.Store.GivenUser();
        var stale = _fixture.Store.GivenIdentity(
            user.Id, IdentityTypes.Firebase, _fixture.HashOfSubject("firebase-uid-OLD"), Google, ProviderUid);

        GivenFirebaseVerifies();

        await Sut.BindFirebaseAsync(user.Id, Request(), CancellationToken.None);

        _fixture.Store.Identities.Count.ShouldBe(1);
        stale.IdentifierHash.ShouldBe(_fixture.HashOfSubject(Uid));
    }

    [Fact]
    public async Task BindingWhenTheProviderKeyBelongsToAnotherAccountIsAConflict()
    {
        var caller = _fixture.Store.GivenUser();
        var other = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(
            other.Id, IdentityTypes.Firebase, _fixture.HashOfSubject("uid-other"), Google, ProviderUid);

        GivenFirebaseVerifies();

        var thrown = await Should.ThrowAsync<ConflictException>(() =>
            Sut.BindFirebaseAsync(caller.Id, Request(), CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.FirebaseIdentityAlreadyBound);
    }

    [Fact]
    public async Task AVerifierFailurePropagatesUnchanged()
    {
        _fixture.Firebase.VerifyIdTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new UnauthorizedException(
                ErrorCodes.FirebaseIdTokenExpired, "The Firebase sign-in token has expired."));

        var thrown = await Should.ThrowAsync<AppException>(() =>
            Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.FirebaseIdTokenExpired);
        thrown.StatusCode.ShouldBe(401);
    }

    /// <summary>
    /// A token with no provider subject cannot use the fallback, so it must not consult it either -
    /// a lookup on the empty string would match every row that has no subject.
    /// </summary>
    [Fact]
    public async Task ATokenWithNoProviderSubjectDoesNotFallBackOnTheEmptyString()
    {
        var other = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(
            other.Id, IdentityTypes.Firebase, _fixture.HashOfSubject("uid-other"), Google);

        GivenFirebaseVerifies(providerUid: string.Empty);

        var response = await Sut.SignInWithFirebaseAsync(Request(), CancellationToken.None);

        response.Account.ShouldNotBeNull().IsNewUser.ShouldBeTrue();
        response.Account.UserId.ShouldNotBe(other.Id);
    }
}
