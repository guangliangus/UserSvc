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
/// The WeChat mini program, which is the richest resolution in the slice because it has a third
/// key: the phone number the user tapped through.
/// <para>
/// The interesting cases are all about that key - when it links, when it is skipped, and when it
/// loses to the union id.
/// </para>
/// </summary>
public sealed class WechatMiniSignInTests
{
    private const string OpenId = "mini-open-1";
    private const string UnionId = "wx-union-1";
    private const string Phone = "+8613900000000";

    private readonly SocialIdentityFixture _fixture = new();

    private SocialIdentityAppService Sut => _fixture.Sut;

    private static WechatMiniSignInRequest Request(string? phoneCode = null) =>
        new() { Code = "js-code-1", PhoneCode = phoneCode };

    private void GivenSessionReturns(string openId = OpenId, string unionId = "") =>
        _fixture.WechatMini.ExchangeSessionAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new WechatMiniCodeExchange(openId, unionId, "session-key"));

    private void GivenPhoneReturns(string phone = Phone) =>
        _fixture.WechatMini.GetPhoneNumberAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(phone);

    [Fact]
    public async Task AFirstMiniProgramSignInWritesTheMiniProgramProvider()
    {
        GivenSessionReturns(unionId: UnionId);

        var response = await Sut.SignInWithWechatMiniAsync(Request(), CancellationToken.None);

        response.IsNewUser.ShouldBeTrue();
        response.NeedsBindPhone.ShouldBeTrue();

        var identity = _fixture.Store.Identities.ShouldHaveSingleItem();
        identity.IdentityType.ShouldBe(IdentityTypes.WechatMini);
        identity.Provider.ShouldBe(SocialProviders.WechatMiniProgram);
        identity.ProviderUid.ShouldBe(UnionId);
    }

    /// <summary>
    /// A brand-new account is created complete: both identities land in one transaction, so there
    /// is never a committed account with a WeChat identity and no phone number.
    /// </summary>
    [Fact]
    public async Task ANewAccountIsCreatedWithItsPhoneNumberInOneTransaction()
    {
        GivenSessionReturns();
        GivenPhoneReturns();

        var response = await Sut.SignInWithWechatMiniAsync(Request("phone-code-1"), CancellationToken.None);

        response.IsNewUser.ShouldBeTrue();
        response.NeedsBindPhone.ShouldBeFalse();

        _fixture.Store.Identities.Count.ShouldBe(2);
        _fixture.Store.Identities.Select(i => i.IdentityType)
            .ShouldBe([IdentityTypes.WechatMini, IdentityTypes.Phone], ignoreOrder: true);

        var phone = _fixture.Store.Identities.Single(i => i.IdentityType == IdentityTypes.Phone);

        // Through the shared normalizer, which drops the leading plus - so a number typed either
        // way is one account, and registration can find the row this slice wrote.
        phone.IdentifierHash.ShouldBe(_fixture.HashOfPhone(Phone));
    }

    /// <summary>
    /// Somebody who registered by phone and now taps "sign in with WeChat" must get their existing
    /// account. The phone identity is left exactly where it is - only the WeChat identity moves.
    /// </summary>
    [Fact]
    public async Task APhoneNumberLinksTheNewIdentityToTheAccountThatAlreadyOwnsIt()
    {
        var owner = _fixture.Store.GivenUser();
        var phoneIdentity = _fixture.Store.GivenIdentity(
            owner.Id, IdentityTypes.Phone, _fixture.HashOfPhone(Phone));

        GivenSessionReturns();
        GivenPhoneReturns();

        var response = await Sut.SignInWithWechatMiniAsync(Request("phone-code-1"), CancellationToken.None);

        response.IsNewUser.ShouldBeFalse();
        response.UserId.ShouldBe(owner.Id);
        response.NeedsBindPhone.ShouldBeFalse();

        _fixture.Store.Users.Count.ShouldBe(1);
        _fixture.Store.Identities.Count.ShouldBe(2);
        phoneIdentity.UserId.ShouldBe(owner.Id);

        // The resolution already dealt with the phone, so the after-the-fact bind must not run and
        // must not query it a second time.
        _fixture.Store.Reads.Count(r => r.IdentityType == IdentityTypes.Phone).ShouldBe(1);
    }

    /// <summary>
    /// The account is resolved by openid, and the number belongs to somebody else. Moving it would
    /// take a login method away from a user who is not part of this request, so it is logged and
    /// skipped - accounts are never merged automatically once one has been resolved.
    /// </summary>
    [Fact]
    public async Task APhoneNumberOwnedByAnotherAccountIsNeverMerged()
    {
        var resolved = _fixture.Store.GivenUser();
        var other = _fixture.Store.GivenUser();

        _fixture.Store.GivenIdentity(resolved.Id, IdentityTypes.WechatMini, _fixture.HashOfSubject(OpenId));
        _fixture.Store.GivenIdentity(other.Id, IdentityTypes.Phone, _fixture.HashOfPhone(Phone));

        GivenSessionReturns();
        GivenPhoneReturns();

        var response = await Sut.SignInWithWechatMiniAsync(Request("phone-code-1"), CancellationToken.None);

        response.UserId.ShouldBe(resolved.Id);
        response.NeedsBindPhone.ShouldBeTrue();

        _fixture.Store.Identities.Count.ShouldBe(2);
        _fixture.Store.Identities.Single(i => i.IdentityType == IdentityTypes.Phone)
            .UserId.ShouldBe(other.Id);
    }

    /// <summary>
    /// The ordering that decides a real conflict: the union id says WeChat considers these one
    /// person, the phone number is only a hint. A points to the union id, B owns the number, and
    /// the sign-in resolves to A with B untouched.
    /// </summary>
    [Fact]
    public async Task AUnionIdOutranksAConflictingPhoneNumber()
    {
        var unionOwner = _fixture.Store.GivenUser();
        var phoneOwner = _fixture.Store.GivenUser();

        _fixture.Store.GivenIdentity(
            unionOwner.Id, IdentityTypes.Wechat, _fixture.HashOfSubject("wx-open-web"), providerUid: UnionId);
        _fixture.Store.GivenIdentity(phoneOwner.Id, IdentityTypes.Phone, _fixture.HashOfPhone(Phone));

        GivenSessionReturns(unionId: UnionId);
        GivenPhoneReturns();

        var response = await Sut.SignInWithWechatMiniAsync(Request("phone-code-1"), CancellationToken.None);

        response.UserId.ShouldBe(unionOwner.Id);
        response.IsNewUser.ShouldBeFalse();

        // The union-id account gained a mini-program identity and nothing else moved.
        _fixture.Store.Identities.Count(i => i.UserId == unionOwner.Id).ShouldBe(2);
        _fixture.Store.Identities.Count(i => i.UserId == phoneOwner.Id).ShouldBe(1);
    }

    /// <summary>
    /// The account was found by openid and the number is simply one it does not have yet. This is
    /// the case the after-the-fact bind exists for.
    /// </summary>
    [Fact]
    public async Task AnUnclaimedPhoneNumberIsBoundToTheResolvedAccount()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.WechatMini, _fixture.HashOfSubject(OpenId));

        GivenSessionReturns();
        GivenPhoneReturns();

        var response = await Sut.SignInWithWechatMiniAsync(Request("phone-code-1"), CancellationToken.None);

        response.NeedsBindPhone.ShouldBeFalse();
        _fixture.Store.Identities.Count(i => i.IdentityType == IdentityTypes.Phone).ShouldBe(1);
    }

    /// <summary>
    /// WeChat's phone endpoint is the least reliable call in the slice. A sign-in that failed
    /// because a convenience lookup failed would be an outage caused by a nicety.
    /// </summary>
    [Fact]
    public async Task AFailedPhoneLookupDoesNotBlockTheSignIn()
    {
        GivenSessionReturns();
        _fixture.WechatMini.GetPhoneNumberAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new UpstreamException(
                ErrorCodes.UpstreamUnavailable, "WeChat could not provide the phone number."));

        var response = await Sut.SignInWithWechatMiniAsync(Request("phone-code-1"), CancellationToken.None);

        response.IsNewUser.ShouldBeTrue();
        response.NeedsBindPhone.ShouldBeTrue();
        _fixture.Store.Identities.ShouldHaveSingleItem();
    }

    [Fact]
    public async Task NoPhoneCodeMeansThePhoneEndpointIsNeverCalled()
    {
        GivenSessionReturns();

        await Sut.SignInWithWechatMiniAsync(Request(), CancellationToken.None);

        await _fixture.WechatMini.DidNotReceiveWithAnyArgs().GetPhoneNumberAsync(default!, default);
    }

    [Fact]
    public async Task ABlankCodeIsRefusedWithoutCallingWechat()
    {
        var thrown = await Should.ThrowAsync<BadRequestException>(() =>
            Sut.SignInWithWechatMiniAsync(new WechatMiniSignInRequest { Code = "  " }, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.WechatLoginFailed);
        await _fixture.WechatMini.DidNotReceiveWithAnyArgs().ExchangeSessionAsync(default!, default);
    }

    /// <summary>
    /// The real execution strategy replays a transaction body after a transient PostgreSQL
    /// failure. Without the guards in the resolution, the replay inserts every identity twice - and
    /// the second copy would then collide with the unique index, turning a retried transient
    /// failure into a hard conflict.
    /// </summary>
    [Fact]
    public async Task AReplayedTransactionDoesNotDuplicateAnything()
    {
        _fixture.Store.ReplayTransactionOnce = true;
        GivenSessionReturns();
        GivenPhoneReturns();

        var response = await Sut.SignInWithWechatMiniAsync(Request("phone-code-1"), CancellationToken.None);

        response.IsNewUser.ShouldBeTrue();
        _fixture.Store.Users.Count.ShouldBe(1);
        _fixture.Store.Identities.Count.ShouldBe(2);
    }

    [Fact]
    public async Task AReplayedPhoneLinkTransactionDoesNotDuplicateTheIdentity()
    {
        var owner = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(owner.Id, IdentityTypes.Phone, _fixture.HashOfPhone(Phone));

        _fixture.Store.ReplayTransactionOnce = true;
        GivenSessionReturns();
        GivenPhoneReturns();

        await Sut.SignInWithWechatMiniAsync(Request("phone-code-1"), CancellationToken.None);

        _fixture.Store.Identities.Count(i => i.IdentityType == IdentityTypes.WechatMini).ShouldBe(1);
    }

    [Fact]
    public async Task BindingTheMiniProgramWritesItsOwnProvider()
    {
        var user = _fixture.Store.GivenUser();
        GivenSessionReturns();

        await Sut.BindWechatMiniAsync(user.Id, Request(), CancellationToken.None);

        var identity = _fixture.Store.Identities.ShouldHaveSingleItem();
        identity.IdentityType.ShouldBe(IdentityTypes.WechatMini);
        identity.Provider.ShouldBe(SocialProviders.WechatMiniProgram);
    }

    [Fact]
    public async Task BindingAMiniProgramAccountOwnedByAnotherUserIsAConflict()
    {
        var caller = _fixture.Store.GivenUser();
        var other = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(other.Id, IdentityTypes.WechatMini, _fixture.HashOfSubject(OpenId));
        GivenSessionReturns();

        var thrown = await Should.ThrowAsync<ConflictException>(() =>
            Sut.BindWechatMiniAsync(caller.Id, Request(), CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.IdentityAlreadyBound);
    }
}
