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
/// WeChat web OAuth sign-in and binding. The WeChat client is substituted; the account resolution
/// behind it is the real thing.
/// </summary>
public sealed class WechatSignInTests
{
    private const string OpenId = "wx-open-1";
    private const string UnionId = "wx-union-1";

    private readonly SocialIdentityFixture _fixture = new();

    private SocialIdentityAppService Sut => _fixture.Sut;

    private WechatSignInRequest Request => new() { Code = "code-1", State = _fixture.ValidState() };

    private void GivenWechatReturns(string openId = OpenId, string unionId = "") =>
        _fixture.Wechat.ExchangeCodeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new WechatCodeExchange(openId, unionId));

    [Fact]
    public async Task AFirstWechatSignInCreatesAnActiveAccountWithOneIdentity()
    {
        GivenWechatReturns();

        var response = await Sut.SignInWithWechatAsync(Request, CancellationToken.None);

        response.IsNewUser.ShouldBeTrue();
        response.UserId.ShouldBeGreaterThan(0);

        // Nothing but a WeChat identity exists yet, so the client has to be told to collect a phone
        // number - that flag is the entire reason a fresh social account is usable.
        response.NeedsBindPhone.ShouldBeTrue();

        var user = _fixture.Store.Users.ShouldHaveSingleItem();
        user.Status.ShouldBe(UserStatuses.Active);

        var identity = _fixture.Store.Identities.ShouldHaveSingleItem();
        identity.IdentityType.ShouldBe(IdentityTypes.Wechat);

        // Web OAuth writes an empty provider; the mini program writes "miniprogram". The pair
        // (identity_type, provider) is what keeps the two openid spaces apart.
        identity.Provider.ShouldBe(SocialProviders.None);
        identity.IdentifierHash.ShouldBe(_fixture.HashOfSubject(OpenId));

        // Decision 13: the openid is an identifier like any other and is never stored in the clear.
        identity.IdentifierCiphertext.ShouldNotBeEmpty();
        identity.IdentifierCiphertext.ShouldNotContain(OpenId);
        identity.IdentifierKeyVersion.ShouldBe("test");
    }

    [Fact]
    public async Task AReturningWechatUserResolvesToTheSameAccountAndCreatesNothing()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Wechat, _fixture.HashOfSubject(OpenId));
        GivenWechatReturns();

        var response = await Sut.SignInWithWechatAsync(Request, CancellationToken.None);

        response.IsNewUser.ShouldBeFalse();
        response.UserId.ShouldBe(user.Id);
        _fixture.Store.Identities.Count.ShouldBe(1);
    }

    /// <summary>
    /// The union id is the only signal that a mini-program openid and a web openid are one person.
    /// Getting this wrong does not fail loudly - it silently gives one human two accounts.
    /// </summary>
    [Fact]
    public async Task AUnionIdMatchAttachesANewIdentityToTheExistingAccount()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(
            user.Id, IdentityTypes.WechatMini, _fixture.HashOfSubject("mini-open-1"),
            SocialProviders.WechatMiniProgram, UnionId);

        GivenWechatReturns(unionId: UnionId);

        var response = await Sut.SignInWithWechatAsync(Request, CancellationToken.None);

        response.IsNewUser.ShouldBeFalse();
        response.UserId.ShouldBe(user.Id);

        _fixture.Store.Users.Count.ShouldBe(1);
        _fixture.Store.Identities.Count.ShouldBe(2);

        var added = _fixture.Store.Identities.Last();
        added.IdentityType.ShouldBe(IdentityTypes.Wechat);
        added.UserId.ShouldBe(user.Id);
        added.ProviderUid.ShouldBe(UnionId);
        added.ProviderDetails.ShouldContain(UnionId);
    }

    /// <summary>
    /// Unification only ever picks the oldest matching row, because one person legitimately holds
    /// one identity per WeChat application. Picking arbitrarily would make the resolved account
    /// depend on row order.
    /// </summary>
    [Fact]
    public async Task AUnionIdMatchPicksTheEarliestIdentity()
    {
        var older = _fixture.Store.GivenUser();
        var newer = _fixture.Store.GivenUser();

        _fixture.Store.GivenIdentity(
            older.Id, IdentityTypes.WechatMini, _fixture.HashOfSubject("a"),
            SocialProviders.WechatMiniProgram, UnionId);
        _fixture.Store.GivenIdentity(
            newer.Id, IdentityTypes.WechatMini, _fixture.HashOfSubject("b"),
            SocialProviders.WechatMiniProgram, UnionId);

        GivenWechatReturns(unionId: UnionId);

        var response = await Sut.SignInWithWechatAsync(Request, CancellationToken.None);

        response.UserId.ShouldBe(older.Id);
    }

    /// <summary>
    /// A web identity created before the app was bound to an Open Platform account has no union id.
    /// The first sign-in that carries one writes it, which is what makes later unification possible
    /// at all.
    /// </summary>
    [Fact]
    public async Task AUnionIdIsBackfilledOntoAnIdentityThatPredatesIt()
    {
        var user = _fixture.Store.GivenUser();
        var identity = _fixture.Store.GivenIdentity(
            user.Id, IdentityTypes.Wechat, _fixture.HashOfSubject(OpenId));

        GivenWechatReturns(unionId: UnionId);

        await Sut.SignInWithWechatAsync(Request, CancellationToken.None);

        identity.ProviderUid.ShouldBe(UnionId);
        identity.ProviderDetails.ShouldContain(UnionId);
        _fixture.Store.Updated.ShouldContain(identity);
    }

    [Fact]
    public async Task AnIdentityThatAlreadyHoldsTheUnionIdIsNotRewritten()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(
            user.Id, IdentityTypes.Wechat, _fixture.HashOfSubject(OpenId), providerUid: UnionId);

        GivenWechatReturns(unionId: UnionId);

        await Sut.SignInWithWechatAsync(Request, CancellationToken.None);

        _fixture.Store.Updated.ShouldBeEmpty();
        _fixture.Store.SaveCount.ShouldBe(0);
    }

    /// <summary>
    /// WeChat sign-in does not advance <c>last_login_at</c> while LINE and Firebase do. The
    /// divergence is the original's; a dashboard built on that column would shift the day it
    /// started to, so it is pinned here rather than tidied up.
    /// </summary>
    [Fact]
    public async Task WechatSignInDoesNotAdvanceLastLogin()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Wechat, _fixture.HashOfSubject(OpenId));
        GivenWechatReturns();

        await Sut.SignInWithWechatAsync(Request, CancellationToken.None);

        user.LastLoginAt.ShouldBeNull();
    }

    /// <summary>
    /// The state is checked before the network call, so a redirect this server did not start costs
    /// no WeChat round trip.
    /// </summary>
    [Fact]
    public async Task AnUnverifiableStateIsRefusedWithoutCallingWechat()
    {
        var thrown = await Should.ThrowAsync<BadRequestException>(() =>
            Sut.SignInWithWechatAsync(
                new WechatSignInRequest { Code = "code-1", State = "forged" }, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.InvalidState);
        await _fixture.Wechat.DidNotReceiveWithAnyArgs().ExchangeCodeAsync(default!, default);
    }

    /// <summary>
    /// A refusal from WeChat is the caller's problem (400); an unreachable WeChat is not (502). The
    /// adapters keep them apart and the sign-in path must not collapse them, or every user is told
    /// their code was bad during an outage.
    /// </summary>
    [Fact]
    public async Task AWechatRefusalIsReportedAsAFailedSignIn()
    {
        _fixture.Wechat.ExchangeCodeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new WechatRejectedException("WeChat rejected the sign-in code (error 40029)."));

        var thrown = await Should.ThrowAsync<AppException>(() =>
            Sut.SignInWithWechatAsync(Request, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.WechatLoginFailed);
        thrown.StatusCode.ShouldBe(400);
    }

    [Fact]
    public async Task AnUnreachableWechatStaysA502()
    {
        _fixture.Wechat.ExchangeCodeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new UpstreamException(ErrorCodes.UpstreamUnavailable, "WeChat could not be reached."));

        var thrown = await Should.ThrowAsync<AppException>(() =>
            Sut.SignInWithWechatAsync(Request, CancellationToken.None));

        thrown.StatusCode.ShouldBe(502);
    }

    /// <summary>
    /// A 200 from WeChat with no openid must never be hashed: the empty string has one blind index,
    /// so every such response would resolve to one shared account.
    /// </summary>
    [Fact]
    public async Task AnEmptyOpenIdIsRefusedRatherThanHashed()
    {
        GivenWechatReturns(openId: "   ");

        var thrown = await Should.ThrowAsync<BadRequestException>(() =>
            Sut.SignInWithWechatAsync(Request, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.WechatLoginFailed);
        _fixture.Store.Identities.ShouldBeEmpty();
    }

    [Fact]
    public async Task ANonActiveAccountIsRefusedWithoutSigningIn()
    {
        var user = _fixture.Store.GivenUser(UserStatuses.Disabled);
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Wechat, _fixture.HashOfSubject(OpenId));
        GivenWechatReturns();

        var thrown = await Should.ThrowAsync<ForbiddenException>(() =>
            Sut.SignInWithWechatAsync(Request, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.AccountNotActivated);
    }

    // ------------------------------------------------------------------ binding

    [Fact]
    public async Task BindingAttachesTheIdentityToTheCallersAccount()
    {
        var user = _fixture.Store.GivenUser();
        GivenWechatReturns(unionId: UnionId);

        await Sut.BindWechatAsync(user.Id, Request, CancellationToken.None);

        var identity = _fixture.Store.Identities.ShouldHaveSingleItem();
        identity.UserId.ShouldBe(user.Id);
        identity.IdentityType.ShouldBe(IdentityTypes.Wechat);
        identity.ProviderUid.ShouldBe(UnionId);
    }

    /// <summary>Re-binding the same provider account to the same user is a no-op, not an error.</summary>
    [Fact]
    public async Task BindingAnIdentityTheCallerAlreadyOwnsChangesNothing()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Wechat, _fixture.HashOfSubject(OpenId));
        GivenWechatReturns();

        await Sut.BindWechatAsync(user.Id, Request, CancellationToken.None);

        _fixture.Store.Identities.Count.ShouldBe(1);
        _fixture.Store.SaveCount.ShouldBe(0);
    }

    [Fact]
    public async Task BindingAnIdentityOwnedByAnotherAccountIsAConflict()
    {
        var caller = _fixture.Store.GivenUser();
        var other = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(other.Id, IdentityTypes.Wechat, _fixture.HashOfSubject(OpenId));
        GivenWechatReturns();

        var thrown = await Should.ThrowAsync<ConflictException>(() =>
            Sut.BindWechatAsync(caller.Id, Request, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.IdentityAlreadyBound);
        _fixture.Store.Identities.Count.ShouldBe(1);
    }

    /// <summary>
    /// The precheck above is advisory. Correctness is the partial unique index, and the loser of a
    /// race has to be told the same thing the second caller was told - not shown a raw constraint
    /// violation.
    /// </summary>
    [Fact]
    public async Task LosingTheInsertRaceIsReportedAsAlreadyBound()
    {
        var caller = _fixture.Store.GivenUser();
        var other = _fixture.Store.GivenUser();
        GivenWechatReturns();

        _fixture.Store.BeforeNextSave = () => _fixture.Store.GivenIdentity(
            other.Id, IdentityTypes.Wechat, _fixture.HashOfSubject(OpenId));

        var thrown = await Should.ThrowAsync<ConflictException>(() =>
            Sut.BindWechatAsync(caller.Id, Request, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.IdentityAlreadyBound);
    }

    /// <summary>
    /// The same WeChat refusal reports a different code on the bind path, because the client's
    /// reaction differs: a failed sign-in restarts sign-in, a failed bind returns to settings.
    /// </summary>
    [Fact]
    public async Task AWechatRefusalOnTheBindPathReportsBindFailed()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Wechat.ExchangeCodeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new WechatRejectedException("WeChat rejected the sign-in code (error 40029)."));

        var thrown = await Should.ThrowAsync<AppException>(() =>
            Sut.BindWechatAsync(user.Id, Request, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.BindFailed);
    }
}
