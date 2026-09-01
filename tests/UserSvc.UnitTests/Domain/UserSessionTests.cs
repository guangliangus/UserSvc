using Shouldly;
using UserSvc.Domain.Abstractions;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Auth.Events;
using Xunit;

namespace UserSvc.UnitTests.Domain;

/// <summary>
/// Decision 04: <see cref="UserSession"/> is deliberately rich, because breaking one of its
/// invariants is a security incident rather than a data error. These tests run entirely in
/// memory — no database, no Redis, no HTTP — and finish in milliseconds.
/// <para>
/// Rotation, replay detection and refresh expiry are <b>not</b> tested here any more: OpenIddict
/// owns them (decision 10), and asserting them against a hand-rolled reimplementation would only
/// prove the reimplementation agrees with itself. What is left is what the aggregate still decides.
/// </para>
/// </summary>
public sealed class UserSessionTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);

    private static UserSession NewSession(string authorizationId = "auth-1") =>
        UserSession.Start(
            "sid-1", 1024,
            new DeviceDescriptor("dev-1", "iPhone 15 Pro", "IOS", "3.2.0", "203.0.113.7", "ua"),
            authorizationId, Now);

    [Fact]
    public void StartingASessionCapturesTheDeviceAndOpensItActive()
    {
        var session = NewSession();

        session.SessionId.ShouldBe("sid-1");
        session.UserId.ShouldBe(1024);
        session.DeviceId.ShouldBe("dev-1");
        session.DeviceName.ShouldBe("iPhone 15 Pro");
        session.Platform.ShouldBe("IOS");
        session.IsActive.ShouldBeTrue();
        session.CreatedAt.ShouldBe(Now);
        session.LastSeenAt.ShouldBe(Now);
        session.RevokedAt.ShouldBeNull();
    }

    [Fact]
    public void TheAuthorizationIdRoundTripsSoTheChainCanBeRevokedLater()
    {
        var session = NewSession("011f2e3d-4c5b-6a79-8899-aabbccddeeff");

        session.AuthorizationId.ShouldBe("011f2e3d-4c5b-6a79-8899-aabbccddeeff");
    }

    [Fact]
    public void ASessionWithoutAnAuthorizationIdIsRefused()
    {
        // Without it a device sign-out could revoke the row but not the refresh chain, which is the
        // failure that looks like success.
        var error = Should.Throw<DomainRuleException>(() => NewSession(authorizationId: " "));

        error.ErrorCode.ShouldBe("AUTHORIZATION_ID_REQUIRED");
    }

    [Fact]
    public void ASessionWithoutAServerGeneratedIdIsRefused()
    {
        var error = Should.Throw<DomainRuleException>(() => UserSession.Start(
            string.Empty, 1024,
            new DeviceDescriptor("dev-1", "iPhone", "IOS", "3.2.0", "203.0.113.7", "ua"),
            "auth-1", Now));

        error.ErrorCode.ShouldBe("SESSION_ID_REQUIRED");
    }

    [Fact]
    public void TouchingASessionMovesLastSeenAt()
    {
        var session = NewSession();

        session.Touch(Now.AddMinutes(9));

        session.LastSeenAt.ShouldBe(Now.AddMinutes(9));
    }

    [Fact]
    public void TouchingARevokedSessionDoesNotBringItBack()
    {
        var session = NewSession();
        session.Revoke(RevocationReasons.Self, Now);

        session.Touch(Now.AddMinutes(9));

        session.IsActive.ShouldBeFalse();
        session.LastSeenAt.ShouldBe(Now, "a dead session is not 'seen' just because a token turned up");
    }

    [Fact]
    public void RevokingRecordsTheReasonAndRaisesTheEvent()
    {
        var session = NewSession();

        session.Revoke(RevocationReasons.OtherDevice, Now.AddMinutes(3));

        session.IsActive.ShouldBeFalse();
        session.RevokedBy.ShouldBe(RevocationReasons.OtherDevice);
        session.RevokedAt.ShouldBe(Now.AddMinutes(3));

        var revoked = session.DomainEvents.OfType<SessionRevoked>().ShouldHaveSingleItem();
        revoked.SessionId.ShouldBe("sid-1");
        revoked.UserId.ShouldBe(1024);
        revoked.Reason.ShouldBe(RevocationReasons.OtherDevice);
    }

    [Fact]
    public void RevokingTwiceIsIdempotentAndRaisesOneEvent()
    {
        var session = NewSession();

        session.Revoke(RevocationReasons.Self, Now);
        session.Revoke(RevocationReasons.Admin, Now.AddMinutes(1));

        session.DomainEvents.OfType<SessionRevoked>().ShouldHaveSingleItem();
        session.RevokedBy.ShouldBe(RevocationReasons.Self, "the first revocation carries the real reason");
        session.RevokedAt.ShouldBe(Now);
    }

    [Fact]
    public void AReplayRaisesTheSecurityAlertAndTakesTheSessionDown()
    {
        var session = NewSession();

        session.RevokeAsReplayed(Now.AddMinutes(5));

        session.IsActive.ShouldBeFalse();
        session.RevokedBy.ShouldBe(RevocationReasons.TokenReplay);

        var replay = session.DomainEvents.OfType<RefreshTokenReplayDetected>().ShouldHaveSingleItem();
        replay.SessionId.ShouldBe("sid-1");
        replay.DeviceId.ShouldBe("dev-1");
        replay.OccurredAt.ShouldBe(Now.AddMinutes(5));

        // The alert and the revocation are separate facts: consumers of one are not consumers of the
        // other.
        session.DomainEvents.OfType<SessionRevoked>().ShouldHaveSingleItem();
    }
}
