using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Application.Ports.External;
using UserSvc.Domain.Users;
using Xunit;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// The writes the spec calls best effort, against the failure shape they were originally blind to.
/// <para>
/// <b>Why this file exists.</b> Every one of these helpers used to catch <c>AppException</c> alone,
/// and <c>UnitOfWork</c> only translates two things into that vocabulary: the xmin concurrency
/// token and SQLSTATE 23505. A check-constraint violation, a foreign key, a statement timeout or a
/// dropped connection arrives as a plain <c>DbUpdateException</c> - so the narrow filter turned a
/// bookkeeping failure into a failed sign-in for a user whose credential was perfectly good and
/// whose account had already been resolved. These cases pin the broadened behaviour so it cannot
/// quietly narrow again.
/// </para>
/// </summary>
public sealed class BestEffortWriteTests
{
    private const string OpenId = "wx-open-1";
    private const string UnionId = "wx-union-1";

    private readonly SocialIdentityFixture _fixture = new();

    private SocialIdentityAppService Sut => _fixture.Sut;

    /// <summary>The shape EF hands up for anything that is not a unique violation.</summary>
    private static Exception UntranslatedDatabaseFailure() =>
        new InvalidOperationException("relation \"identity.user_identities\" has no column \"provider\"");

    [Fact]
    public async Task AFailedUnionIdBackfillDoesNotFailTheWechatSignIn()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Wechat, _fixture.HashOfSubject(OpenId));

        _fixture.Wechat.ExchangeCodeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new WechatCodeExchange(OpenId, UnionId));

        // The backfill is the only write on this path, so the very next save is it.
        _fixture.Store.FailNextSaveWith = UntranslatedDatabaseFailure();

        var response = await Sut.SignInWithWechatAsync(
            new WechatSignInRequest { Code = "code", State = _fixture.ValidState() },
            CancellationToken.None);

        response.UserId.ShouldBe(user.Id);
        response.IsNewUser.ShouldBeFalse();
    }

    [Fact]
    public async Task AFailedLastLoginWriteDoesNotFailTheLineSignIn()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Line, _fixture.HashOfSubject("line-sub-1"));

        _fixture.Line.VerifyIdTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new LineIdentity("line-sub-1", string.Empty, "Ada", string.Empty));

        _fixture.Store.FailNextSaveWith = UntranslatedDatabaseFailure();

        var response = await Sut.SignInWithLineAsync(
            new LineSignInRequest { IdToken = "id-token", State = _fixture.ValidState() },
            CancellationToken.None);

        response.UserId.ShouldBe(user.Id);
    }

    [Fact]
    public async Task AFailedFirebaseSelfHealDoesNotFailTheFirebaseSignIn()
    {
        var user = _fixture.Store.GivenUser();

        // Bound under an OLD uid, so the uid lookup misses and the provider-key fallback wins -
        // which is the path that then tries to re-point the stored identifier.
        _fixture.Store.GivenIdentity(
            user.Id,
            IdentityTypes.Firebase,
            _fixture.HashOfSubject("stale-uid"),
            provider: "google.com",
            providerUid: "google-sub-1");

        _fixture.Firebase.VerifyIdTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new FirebaseIdentity(
                "fresh-uid", "google.com", "google-sub-1", string.Empty, false, string.Empty, string.Empty));

        _fixture.Store.FailNextSaveWith = UntranslatedDatabaseFailure();

        var response = await Sut.SignInWithFirebaseAsync(
            new FirebaseSignInRequest { FirebaseIdToken = "token", Provider = "google.com" },
            CancellationToken.None);

        response.NeedsBindingConsent.ShouldBeFalse();
        response.Account.ShouldNotBeNull();
        response.Account.UserId.ShouldBe(user.Id);
    }

    /// <summary>
    /// The mini program's phone step is best effort in the spec's own words, and the adapter is the
    /// least reliable call in the slice. An exception shape the adapter never wrapped must not cost
    /// the user their sign-in either.
    /// </summary>
    [Fact]
    public async Task AnUnwrappedPhoneLookupFailureDoesNotFailTheMiniProgramSignIn()
    {
        _fixture.WechatMini.ExchangeSessionAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new WechatMiniCodeExchange(OpenId, string.Empty, "session-key"));

        _fixture.WechatMini.GetPhoneNumberAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns<string>(_ => throw new HttpRequestException("connection reset by peer"));

        var response = await Sut.SignInWithWechatMiniAsync(
            new WechatMiniSignInRequest { Code = "js-code", PhoneCode = "phone-code" },
            CancellationToken.None);

        response.IsNewUser.ShouldBeTrue();
        response.NeedsBindPhone.ShouldBeTrue();
    }

    /// <summary>
    /// Cancellation stays an exception. Swallowing it would report a sign-in as complete to a
    /// caller that has already gone, and would hide the abandonment from every dashboard.
    /// </summary>
    [Fact]
    public async Task ACancelledBestEffortWriteStillCancels()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Wechat, _fixture.HashOfSubject(OpenId));

        _fixture.Wechat.ExchangeCodeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new WechatCodeExchange(OpenId, UnionId));

        _fixture.Store.FailNextSaveWith = new OperationCanceledException();

        await Should.ThrowAsync<OperationCanceledException>(() => Sut.SignInWithWechatAsync(
            new WechatSignInRequest { Code = "code", State = _fixture.ValidState() },
            CancellationToken.None));
    }

    /// <summary>
    /// A mini-program sign-in resolved by openid, for an account that already has a different phone
    /// number: the number WeChat reports is not added as a second active PHONE identity.
    /// <para>
    /// The spec leaves this to a per-user partial unique index that this repo's
    /// <c>user_identities</c> does not have, so without the guard the account quietly gains a
    /// second login identifier its owner never asked for - and every flow that reads "the
    /// account's phone number" starts depending on row order.
    /// </para>
    /// </summary>
    [Fact]
    public async Task ASecondPhoneNumberIsNotAddedToAnAccountThatAlreadyHasOne()
    {
        var user = _fixture.Store.GivenUser();
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.WechatMini, _fixture.HashOfSubject(OpenId));
        _fixture.Store.GivenIdentity(user.Id, IdentityTypes.Phone, _fixture.HashOfPhone("+8613800000000"));

        _fixture.WechatMini.ExchangeSessionAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new WechatMiniCodeExchange(OpenId, string.Empty, "session-key"));

        _fixture.WechatMini.GetPhoneNumberAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("+8613900000000");

        var response = await Sut.SignInWithWechatMiniAsync(
            new WechatMiniSignInRequest { Code = "js-code", PhoneCode = "phone-code" },
            CancellationToken.None);

        response.UserId.ShouldBe(user.Id);
        _fixture.Store.Identities
            .Count(i => i.UserId == user.Id && i.IdentityType == IdentityTypes.Phone)
            .ShouldBe(1);
    }

    /// <summary>
    /// The insert race for a Firebase token whose <c>identities</c> claim carried no subject.
    /// <para>
    /// There is no provider key to re-read the winner by, so only the
    /// (identity_type, identifier_hash) index can have fired. Before the fix that collision escaped
    /// untranslated, and the client was handed a 409 whose message named a PostgreSQL index.
    /// </para>
    /// </summary>
    [Fact]
    public async Task AFirebaseBindRaceWithNoProviderSubjectReportsTheBindingConflict()
    {
        var caller = _fixture.Store.GivenUser();
        var stranger = _fixture.Store.GivenUser();

        _fixture.Firebase.VerifyIdTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new FirebaseIdentity(
                "uid-1", "google.com", string.Empty, string.Empty, false, string.Empty, string.Empty));

        // Somebody else binds the same uid between the precheck and the insert.
        _fixture.Store.BeforeNextSave = () => _fixture.Store.GivenIdentity(
            stranger.Id, IdentityTypes.Firebase, _fixture.HashOfSubject("uid-1"), provider: "google.com");

        var error = await Should.ThrowAsync<ConflictException>(() => Sut.BindFirebaseAsync(
            caller.Id,
            new FirebaseSignInRequest { FirebaseIdToken = "token", Provider = "google.com" },
            CancellationToken.None));

        error.ErrorCode.ShouldBe(ErrorCodes.FirebaseIdentityAlreadyBound);
        error.Message.ShouldNotContain("constraint");
    }
}
