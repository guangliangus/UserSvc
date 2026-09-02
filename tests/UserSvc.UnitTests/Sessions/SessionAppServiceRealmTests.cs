using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Sessions;
using UserSvc.Application.Ports.Auth;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Users;
using Xunit;

namespace UserSvc.UnitTests.Sessions;

/// <summary>
/// Sessions live in two realms that number their accounts independently, so <c>user_id</c> alone
/// names two different people. These tests pin the consequences at the seam where they were real:
/// the same integer signing in from both planes, the device cap, the device list, and signing one
/// device out.
/// <para>
/// Every case uses <b>the same id in both realms on purpose</b> — that is the only shape in which
/// the defect showed itself, and a test that used different ids would pass with the realm filter
/// removed.
/// </para>
/// </summary>
public sealed class SessionAppServiceRealmTests
{
    private const int SharedId = 100;

    private readonly FakeSessionRepository _sessions = new();
    private readonly IUserRepository _users = Substitute.For<IUserRepository>();
    private readonly ISessionRevocationStore _revocations = Substitute.For<ISessionRevocationStore>();
    private readonly ITokenChainRevoker _chains = Substitute.For<ITokenChainRevoker>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 8, 0, 0, TimeSpan.Zero));

    private readonly AuthSessionOptions _options = new() { MaxActiveDevices = 2 };

    public SessionAppServiceRealmTests() =>
        _users.FindByIdAsync(SharedId, Arg.Any<CancellationToken>())
            .Returns(new User { Id = SharedId, Status = UserStatuses.Active });

    private SessionAppService Sut => new(
        _sessions,
        _users,
        _revocations,
        _chains,
        _unitOfWork,
        _clock,
        Options.Create(_options),
        NullLogger<SessionAppService>.Instance);

    private static DeviceDescriptor Device(string deviceId) =>
        new(deviceId, "Chrome", "WEB", "1.0.0", "203.0.113.7", "ua");

    private UserSession Seed(SessionSubject subject, string sessionId, string deviceId) =>
        _sessions.Seed(UserSession.Start(
            sessionId, subject, Device(deviceId), "auth-" + sessionId, _clock.UtcNow));

    // ------------------------------------------------------- the reported defect

    /// <summary>
    /// The collision reproduced against the live database before this column existed: consumer 100
    /// and back-office 100 signing in from the same <c>device_id</c> hit
    /// <c>ix_user_sessions_user_id_device_id</c> and the second one could not sign in at all. With
    /// the realm in the key they are two rows, and neither supersedes the other.
    /// </summary>
    [Fact]
    public async Task TheSameIdInBothRealmsCanHoldASessionOnTheSameDevice()
    {
        await Sut.StartAsync(SharedId, "sid-consumer", "auth-c", Device("shared-device"), default);
        await Sut.StartForBackOfficeAsync(SharedId, "sid-backoffice", "auth-b", Device("shared-device"), default);

        _sessions.Rows.Count.ShouldBe(2);
        _sessions.Rows.Count(s => s.IsActive).ShouldBe(
            2, "neither sign-in may supersede the other: they are different people");

        _sessions.Rows.Single(s => s.SessionId == "sid-consumer").Realm
            .ShouldBe(SessionRealms.Consumer);
        _sessions.Rows.Single(s => s.SessionId == "sid-backoffice").Realm
            .ShouldBe(SessionRealms.BackOffice);
    }

    [Fact]
    public async Task ASecondSignInOnTheSameDeviceStillSupersedesWithinOneRealm()
    {
        var first = Seed(SessionSubject.Consumer(SharedId), "sid-1", "same-device");

        await Sut.StartAsync(SharedId, "sid-2", "auth-2", Device("same-device"), default);

        first.IsActive.ShouldBeFalse("the partial unique index would refuse the insert otherwise");
        first.RevokedBy.ShouldBe(RevocationReasons.Superseded);
    }

    /// <summary>
    /// The device cap counts one realm's devices. Before the column, an operator's two open
    /// sessions filled a consumer's cap and the consumer's sign-in evicted one of them.
    /// </summary>
    [Fact]
    public async Task TheDeviceCapCountsOnlyTheSubjectsOwnRealm()
    {
        var operatorA = Seed(SessionSubject.BackOffice(SharedId), "bo-1", "bo-device-1");
        var operatorB = Seed(SessionSubject.BackOffice(SharedId), "bo-2", "bo-device-2");

        // MaxActiveDevices is 2 and the back office already holds two.
        await Sut.StartAsync(SharedId, "sid-consumer", "auth-c", Device("phone"), default);

        operatorA.IsActive.ShouldBeTrue("a consumer sign-in must not evict an operator's session");
        operatorB.IsActive.ShouldBeTrue();
        _sessions.Rows.Single(s => s.SessionId == "sid-consumer").IsActive.ShouldBeTrue();

        await _chains.DidNotReceiveWithAnyArgs().RevokeChainAsync(default!, default);
    }

    [Fact]
    public async Task TheDeviceCapStillEvictsTheLeastRecentlySeenSessionInsideOneRealm()
    {
        var oldest = Seed(SessionSubject.Consumer(SharedId), "sid-1", "device-1");
        var newer = Seed(SessionSubject.Consumer(SharedId), "sid-2", "device-2");
        _clock.Advance(TimeSpan.FromMinutes(5));
        newer.Touch(_clock.UtcNow);

        await Sut.StartAsync(SharedId, "sid-3", "auth-3", Device("device-3"), default);

        oldest.IsActive.ShouldBeFalse();
        oldest.RevokedBy.ShouldBe(RevocationReasons.DeviceLimit);
        newer.IsActive.ShouldBeTrue();
    }

    [Fact]
    public async Task TheDeviceListShowsOnlyTheCallersOwnRealm()
    {
        Seed(SessionSubject.Consumer(SharedId), "sid-consumer", "phone");
        Seed(SessionSubject.BackOffice(SharedId), "sid-backoffice", "workstation");

        var consumerDevices = await Sut.ListDevicesAsync(
            SessionSubject.Consumer(SharedId), "sid-consumer", default);

        consumerDevices.ShouldHaveSingleItem().SessionId.ShouldBe("sid-consumer");

        var backOfficeDevices = await Sut.ListDevicesAsync(
            SessionSubject.BackOffice(SharedId), "sid-backoffice", default);

        backOfficeDevices.ShouldHaveSingleItem().SessionId.ShouldBe("sid-backoffice");
    }

    /// <summary>
    /// A session found by <c>sid</c> is then checked against the whole subject. Matching the id
    /// alone let either plane sign the other's device out, and it looked like signing out one's own.
    /// </summary>
    [Fact]
    public async Task SigningOutADeviceInTheOtherRealmIsANotFound()
    {
        var operatorSession = Seed(SessionSubject.BackOffice(SharedId), "bo-1", "workstation");

        var error = await Should.ThrowAsync<NotFoundException>(() => Sut.RevokeDeviceAsync(
            SessionSubject.Consumer(SharedId), "bo-1", RevocationReasons.OtherDevice, default));

        error.ErrorCode.ShouldBe(ErrorCodes.SessionNotFound);
        operatorSession.IsActive.ShouldBeTrue();
        await _chains.DidNotReceiveWithAnyArgs().RevokeChainAsync(default!, default);
    }

    [Fact]
    public async Task SigningOutOnesOwnDeviceStillWorksInEitherRealm()
    {
        Seed(SessionSubject.BackOffice(SharedId), "bo-1", "workstation");

        await Sut.RevokeDeviceAsync(
            SessionSubject.BackOffice(SharedId), "bo-1", RevocationReasons.Self, default);

        _sessions.Rows.Single(s => s.SessionId == "bo-1").IsActive.ShouldBeFalse();
        await _chains.Received(1).RevokeChainAsync("auth-bo-1", Arg.Any<CancellationToken>());
        await _revocations.Received(1).RevokeAsync("bo-1", Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The most damaging of the cross-realm sweeps. Closing consumer 100's account used to sign
    /// back-office 100 out of the back office, stamping DEREGISTERED on the audit trail of somebody
    /// who deregistered nothing.
    /// </summary>
    [Fact]
    public async Task SignOutEverywhereStopsAtTheRealmBoundary()
    {
        var consumerSession = Seed(SessionSubject.Consumer(SharedId), "sid-consumer", "phone");
        var operatorSession = Seed(SessionSubject.BackOffice(SharedId), "bo-1", "workstation");

        await Sut.RevokeAllAsync(
            SessionSubject.Consumer(SharedId), RevocationReasons.Deregistered, default);

        consumerSession.IsActive.ShouldBeFalse();
        consumerSession.RevokedBy.ShouldBe(RevocationReasons.Deregistered);
        operatorSession.IsActive.ShouldBeTrue("the operator was never asked and never signed out");

        await _chains.Received(1).RevokeChainAsync("auth-sid-consumer", Arg.Any<CancellationToken>());
        await _chains.DidNotReceive().RevokeChainAsync("auth-bo-1", Arg.Any<CancellationToken>());
    }

    // ------------------------------------------- the paths that stay realm-free

    /// <summary>
    /// A refresh carries a <c>sid</c> and nothing else, and a <c>sid</c> is unique across the whole
    /// table. Requiring a realm here would mean deriving one to feed a lookup that does not need
    /// it, and a wrongly derived realm would report a live session as dead.
    /// </summary>
    [Fact]
    public async Task ARefreshTouchesTheSessionBySidAloneInEitherRealm()
    {
        Seed(SessionSubject.BackOffice(SharedId), "bo-1", "workstation");
        Seed(SessionSubject.Consumer(SharedId), "sid-consumer", "phone");
        _clock.Advance(TimeSpan.FromMinutes(7));

        (await Sut.TryTouchAsync("bo-1", default)).ShouldBeTrue();
        (await Sut.TryTouchAsync("sid-consumer", default)).ShouldBeTrue();

        _sessions.Rows.Single(s => s.SessionId == "bo-1").LastSeenAt.ShouldBe(_clock.UtcNow);
        _sessions.SubjectReads.ShouldBe(0, "the refresh path never asks a subject-scoped question");
    }

    [Fact]
    public async Task AReplayIsRecordedWithTheRealmOfTheSessionItLeakedFrom()
    {
        Seed(SessionSubject.BackOffice(SharedId), "bo-1", "workstation");

        (await Sut.HandleRefreshTokenReplayAsync("bo-1", default)).ShouldBeTrue();

        var session = _sessions.Rows.Single(s => s.SessionId == "bo-1");
        session.RevokedBy.ShouldBe(RevocationReasons.TokenReplay);

        // The outbox alert is the only lasting trace of a leak, and an id without its realm names
        // two people.
        session.DomainEvents
            .OfType<UserSvc.Domain.Auth.Events.RefreshTokenReplayDetected>()
            .ShouldHaveSingleItem()
            .Realm.ShouldBe(SessionRealms.BackOffice);
    }

    // ------------------------------------------------------ consumer entry point

    [Fact]
    public async Task AConsumerSignInStillChecksTheConsumerAccountAndOnlyThat()
    {
        _users.FindByIdAsync(SharedId, Arg.Any<CancellationToken>()).Returns((User?)null);

        var error = await Should.ThrowAsync<NotFoundException>(
            () => Sut.StartAsync(SharedId, "sid-1", "auth-1", Device("phone"), default));

        error.ErrorCode.ShouldBe(ErrorCodes.UserNotFound);
        _sessions.Rows.ShouldBeEmpty();
    }

    [Fact]
    public async Task ABackOfficeSignInDoesNotConsultTheConsumerAccountTable()
    {
        // identity.users has no row 100; iam.backend_users does. Looking one plane's id up in the
        // other plane's table is wrong twice over, so this entry point does not.
        _users.FindByIdAsync(SharedId, Arg.Any<CancellationToken>()).Returns((User?)null);

        await Sut.StartForBackOfficeAsync(SharedId, "bo-1", "auth-b", Device("workstation"), default);

        _sessions.Rows.ShouldHaveSingleItem().Realm.ShouldBe(SessionRealms.BackOffice);
    }
}
