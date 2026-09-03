using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Domain.Users;
using Xunit;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// Unlinking a third-party account. The interesting rule is the refusal: an account must never be
/// left with no way in.
/// </summary>
public sealed class UnbindTests
{
    private readonly SocialIdentityFixture _fixture = new();

    private SocialIdentityAppService Sut => _fixture.Sut;

    /// <summary>
    /// Retired, not deleted: the row drops out of the partial unique index so the provider account
    /// can be linked elsewhere, while the history of it having been here survives an
    /// account-takeover investigation.
    /// </summary>
    [Fact]
    public async Task UnbindingRetiresTheRowRatherThanDeletingIt()
    {
        var user = _fixture.Store.GivenUser();
        var wechat = _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Wechat, "hash-wechat");
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Phone, "hash-phone");

        await Sut.UnbindAsync(user.Id, IdentityTypes.Wechat, SocialProviders.None, CancellationToken.None);

        _fixture.Store.Identities.Count.ShouldBe(2);
        wechat.Status.ShouldBe(UserStatuses.Unbound);
        wechat.UpdatedAt.ShouldBe(_fixture.Clock.UtcNow);
        _fixture.Store.Updated.ShouldContain(wechat);
    }

    [Fact]
    public async Task TheIdentityTypeIsMatchedCaseInsensitively()
    {
        var user = _fixture.Store.GivenUser();
        var line = _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Line, "hash-line");
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Email, "hash-email");

        await Sut.UnbindAsync(user.Id, "line", SocialProviders.None, CancellationToken.None);

        line.Status.ShouldBe(UserStatuses.Unbound);
    }

    /// <summary>
    /// The mini program and web WeChat are two identities of the same type, told apart only by the
    /// provider column. Unbinding one must not touch the other.
    /// </summary>
    [Fact]
    public async Task TheProviderPicksBetweenTwoIdentitiesOfTheSameType()
    {
        var user = _fixture.Store.GivenUser();
        var web = _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Wechat, "hash-web");
        var mini = _fixture.Store.GivenIdentity(
            user.Id, IdentityTypes.WechatMini, "hash-mini", SocialProviders.WechatMiniProgram);

        await Sut.UnbindAsync(
            user.Id, IdentityTypes.WechatMini, SocialProviders.WechatMiniProgram, CancellationToken.None);

        mini.Status.ShouldBe(UserStatuses.Unbound);
        web.Status.ShouldBe(UserStatuses.Active);
    }

    /// <summary>
    /// Without this the owner would be locked out and support could not recover them, because a
    /// social identity is the only thing that could have proved who they are.
    /// <para>
    /// The code is pinned because it is the whole reason this refusal has one of its own: it used
    /// to answer the generic <see cref="ErrorCodes.Conflict"/>, which kept it out of the error
    /// message bundles - a Thai user was told to add another sign-in method in English or not at
    /// all.
    /// </para>
    /// </summary>
    [Fact]
    public async Task TheOnlyWayIntoAnAccountCannotBeUnbound()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Line, "hash-line");

        var thrown = await Should.ThrowAsync<ConflictException>(() =>
            Sut.UnbindAsync(user.Id, IdentityTypes.Line, SocialProviders.None, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.LastLoginMethod);
        _fixture.Store.Identities.ShouldHaveSingleItem().Status.ShouldBe(UserStatuses.Active);
    }

    /// <summary>A password is a way in, so the last identity may go.</summary>
    [Fact]
    public async Task TheLastIdentityMayGoWhenTheAccountHasAPassword()
    {
        var user = _fixture.Store.GivenUser(passwordHash: "argon2id$...");
        var line = _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Line, "hash-line");

        await Sut.UnbindAsync(user.Id, IdentityTypes.Line, SocialProviders.None, CancellationToken.None);

        line.Status.ShouldBe(UserStatuses.Unbound);
    }

    /// <summary>
    /// A retired row is not a linked account, so unbinding it again is a 404 rather than a second
    /// success - and, importantly, it does not count towards the "other ways in" tally either.
    /// </summary>
    [Fact]
    public async Task AnAlreadyRetiredIdentityIsNotFound()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Phone, "hash-phone");
        _fixture.Store.GivenIdentity(
            user.Id, IdentityTypes.Wechat, "hash-wechat", status: UserStatuses.Unbound);

        var thrown = await Should.ThrowAsync<NotFoundException>(() =>
            Sut.UnbindAsync(user.Id, IdentityTypes.Wechat, SocialProviders.None, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.NotFound);
    }

    [Fact]
    public async Task AnIdentityOnAnotherAccountIsNotFound()
    {
        var caller = _fixture.Store.GivenUser();
        var other = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(other.Id, IdentityTypes.Wechat, "hash-wechat");

        await Should.ThrowAsync<NotFoundException>(() =>
            Sut.UnbindAsync(caller.Id, IdentityTypes.Wechat, SocialProviders.None, CancellationToken.None));
    }

    /// <summary>
    /// Phone, email and passkey are unbound through their own flows, which have preconditions this
    /// endpoint knows nothing about - changing a phone number goes through a verification code, not
    /// through here.
    /// </summary>
    [Theory]
    [InlineData(IdentityTypes.Phone)]
    [InlineData(IdentityTypes.Email)]
    [InlineData(IdentityTypes.Passkey)]
    [InlineData("nonsense")]
    public async Task OnlyThirdPartyIdentitiesAreUnboundHere(string identityType)
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, identityType, "hash-x");
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Line, "hash-line");

        var thrown = await Should.ThrowAsync<BadRequestException>(() =>
            Sut.UnbindAsync(user.Id, identityType, SocialProviders.None, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
    }
}
