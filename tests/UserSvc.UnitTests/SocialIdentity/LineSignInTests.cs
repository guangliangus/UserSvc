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
/// LINE sign-in and binding. Two behaviours here are preserved from the original although they look
/// wrong, and both are pinned by a test so nobody "fixes" them by accident: every failure reports
/// <c>LINE_LOGIN_FAILED</c> including a bad state, and a matching email address merges silently.
/// </summary>
public sealed class LineSignInTests
{
    private const string Sub = "line-sub-1";
    private const string Email = "dana@example.com";

    private readonly SocialIdentityFixture _fixture = new();

    private SocialIdentityAppService Sut => _fixture.Sut;

    private LineSignInRequest Request => new() { IdToken = "id-token-1", State = _fixture.ValidState() };

    private void GivenLineVerifies(string sub = Sub, string email = "", string name = "", string picture = "") =>
        _fixture.Line.VerifyIdTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new LineIdentity(sub, email, name, picture));

    [Fact]
    public async Task AFirstLineSignInWithNoEmailCreatesOneIdentity()
    {
        GivenLineVerifies();

        var response = await Sut.SignInWithLineAsync(Request, CancellationToken.None);

        response.IsNewUser.ShouldBeTrue();
        response.NeedsBindPhone.ShouldBeTrue();

        var identity = _fixture.Store.Identities.ShouldHaveSingleItem();
        identity.IdentityType.ShouldBe(IdentityTypes.Line);

        // LINE has no cross-application identifier, so both provider columns stay empty - which
        // also keeps these rows out of the (provider, provider_uid) unique index.
        identity.Provider.ShouldBe(SocialProviders.None);
        identity.ProviderUid.ShouldBe(string.Empty);
    }

    /// <summary>
    /// The address is bound without a verification code, and that is the point of a federated
    /// sign-in: LINE has just vouched for it. The user can then also sign in by email.
    /// </summary>
    [Fact]
    public async Task AFirstLineSignInWithAnEmailBindsItAsASecondIdentity()
    {
        GivenLineVerifies(email: Email, name: "Dana", picture: "https://line/pic.png");

        var response = await Sut.SignInWithLineAsync(Request, CancellationToken.None);

        response.IsNewUser.ShouldBeTrue();

        _fixture.Store.Identities.Select(i => i.IdentityType)
            .ShouldBe([IdentityTypes.Line, IdentityTypes.Email], ignoreOrder: true);

        var user = _fixture.Store.Users.ShouldHaveSingleItem();
        user.Nickname.ShouldBe("Dana");
        user.Avatar.ShouldBe("https://line/pic.png");

        var lineIdentity = _fixture.Store.Identities.Single(i => i.IdentityType == IdentityTypes.Line);

        // The masked address is recorded for support and audit; the searchable copy lives on the
        // email identity with its own blind index, never twice in the clear.
        lineIdentity.ProviderDetails.ShouldContain("dan***@example.com");
        lineIdentity.ProviderDetails.ShouldNotContain(Email);
    }

    [Fact]
    public async Task AnAccountWithNoNameOrEmailGetsTheDefaultNickname()
    {
        GivenLineVerifies();

        await Sut.SignInWithLineAsync(Request, CancellationToken.None);

        _fixture.Store.Users.ShouldHaveSingleItem().Nickname.ShouldBe(SocialProfileText.DefaultNickname);
    }

    [Fact]
    public async Task AReturningLineUserNeverLooksAtTheEmailAddress()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Line, _fixture.HashOfSubject(Sub));
        GivenLineVerifies(email: Email);

        var response = await Sut.SignInWithLineAsync(Request, CancellationToken.None);

        response.UserId.ShouldBe(user.Id);
        response.IsNewUser.ShouldBeFalse();
        _fixture.Store.Reads.ShouldNotContain(r => r.IdentityType == IdentityTypes.Email);
    }

    /// <summary>
    /// <b>The weakest link in the slice, kept deliberately.</b> Anyone who can obtain a LINE
    /// account asserting an address gains the account registered under it, with no consent screen.
    /// LINE does verify the addresses it releases, which is what makes it defensible; the Firebase
    /// path shows the stronger design. Changing it here would orphan every LINE user who has been
    /// relying on it, so it is pinned rather than quietly altered.
    /// </summary>
    [Fact]
    public async Task AMatchingEmailAddressMergesIntoTheExistingAccountWithoutConsent()
    {
        var owner = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(owner.Id, IdentityTypes.Email, _fixture.HashOfEmail(Email));
        GivenLineVerifies(email: Email);

        var response = await Sut.SignInWithLineAsync(Request, CancellationToken.None);

        response.IsNewUser.ShouldBeFalse();
        response.UserId.ShouldBe(owner.Id);

        _fixture.Store.Users.Count.ShouldBe(1);
        _fixture.Store.Identities.Count.ShouldBe(2);
        _fixture.Store.Identities.Last().IdentityType.ShouldBe(IdentityTypes.Line);
    }

    /// <summary>
    /// LINE reports its own code even for a state failure, while WeChat reports
    /// <c>INVALID_STATE</c>. The LINE clients branch on the one code, so the re-labelling is the
    /// contract.
    /// </summary>
    [Fact]
    public async Task AnUnverifiableStateIsReportedAsALineFailureNotAStateFailure()
    {
        var thrown = await Should.ThrowAsync<AppException>(() =>
            Sut.SignInWithLineAsync(
                new LineSignInRequest { IdToken = "t", State = "forged" }, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.LineLoginFailed);
        thrown.StatusCode.ShouldBe(400);
        await _fixture.Line.DidNotReceiveWithAnyArgs().VerifyIdTokenAsync(default!, default!, default);
    }

    [Fact]
    public async Task TheNonceFromTheStateIsPassedToLine()
    {
        var state = _fixture.ValidState();
        var nonce = _fixture.States.ReadNonce(state);
        GivenLineVerifies();

        await Sut.SignInWithLineAsync(
            new LineSignInRequest { IdToken = "id-token-1", State = state }, CancellationToken.None);

        // Without the nonce, an id_token captured from another session replays cleanly.
        await _fixture.Line.Received(1).VerifyIdTokenAsync("id-token-1", nonce, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ALineRefusalIsReportedAsALineFailure()
    {
        _fixture.Line.VerifyIdTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new LineRejectedException("LINE could not verify the sign-in."));

        var thrown = await Should.ThrowAsync<AppException>(() =>
            Sut.SignInWithLineAsync(Request, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.LineLoginFailed);
    }

    /// <summary>
    /// LINE answers <c>ACCOUNT_DISABLED</c> where WeChat and Firebase answer
    /// <c>ACCOUNT_NOT_ACTIVATED</c> for the identical condition. Two codes for one state is the
    /// original's contract, and the LINE clients branch on this one.
    /// </summary>
    [Fact]
    public async Task ANonActiveAccountReportsAccountDisabledRatherThanNotActivated()
    {
        var user = _fixture.Store.GivenUser(UserStatuses.Disabled);
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Line, _fixture.HashOfSubject(Sub));
        GivenLineVerifies();

        var thrown = await Should.ThrowAsync<ForbiddenException>(() =>
            Sut.SignInWithLineAsync(Request, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.AccountDisabled);
    }

    /// <summary>LINE advances <c>last_login_at</c>; WeChat does not. Both are pinned.</summary>
    [Fact]
    public async Task LineSignInAdvancesLastLogin()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Line, _fixture.HashOfSubject(Sub));
        GivenLineVerifies();

        await Sut.SignInWithLineAsync(Request, CancellationToken.None);

        user.LastLoginAt.ShouldBe(_fixture.Clock.UtcNow);
    }

    [Fact]
    public async Task AnEmptySubjectIsRefusedRatherThanHashed()
    {
        GivenLineVerifies(sub: "  ");

        await Should.ThrowAsync<AppException>(() => Sut.SignInWithLineAsync(Request, CancellationToken.None));

        _fixture.Store.Identities.ShouldBeEmpty();
    }

    // ------------------------------------------------------------------ binding

    [Fact]
    public async Task BindingAttachesALineIdentityToTheCallersAccount()
    {
        var user = _fixture.Store.GivenUser();
        GivenLineVerifies(email: Email, name: "Dana");

        await Sut.BindLineAsync(user.Id, Request, CancellationToken.None);

        var identity = _fixture.Store.Identities.ShouldHaveSingleItem();
        identity.UserId.ShouldBe(user.Id);
        identity.IdentityType.ShouldBe(IdentityTypes.Line);
        identity.ProviderDetails.ShouldContain("Dana");
    }

    [Fact]
    public async Task BindingALineAccountTheCallerAlreadyOwnsChangesNothing()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Line, _fixture.HashOfSubject(Sub));
        GivenLineVerifies();

        await Sut.BindLineAsync(user.Id, Request, CancellationToken.None);

        _fixture.Store.Identities.Count.ShouldBe(1);
    }

    [Fact]
    public async Task BindingALineAccountOwnedByAnotherUserIsAConflict()
    {
        var caller = _fixture.Store.GivenUser();
        var other = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(other.Id, IdentityTypes.Line, _fixture.HashOfSubject(Sub));
        GivenLineVerifies();

        var thrown = await Should.ThrowAsync<ConflictException>(() =>
            Sut.BindLineAsync(caller.Id, Request, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.IdentityAlreadyBound);
    }

    /// <summary>
    /// The bind path keeps LINE's own code rather than <c>BIND_FAILED</c>, unlike WeChat. The
    /// asymmetry is the original's.
    /// </summary>
    [Fact]
    public async Task ALineRefusalOnTheBindPathKeepsTheLineCode()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Line.VerifyIdTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new LineRejectedException("LINE could not verify the sign-in."));

        var thrown = await Should.ThrowAsync<AppException>(() =>
            Sut.BindLineAsync(user.Id, Request, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.LineLoginFailed);
    }
}
