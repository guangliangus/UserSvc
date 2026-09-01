using Shouldly;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Auth.Events;
using Xunit;

namespace UserSvc.UnitTests.Domain;

/// <summary>
/// Decision 04: <see cref="UserSession"/> is deliberately rich, because breaking one of its
/// invariants is a security incident rather than a data error. These tests run entirely in
/// memory — no database, no Redis, no HTTP — and finish in milliseconds.
/// </summary>
public sealed class UserSessionTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan RefreshLifetime = TimeSpan.FromDays(30);

    private static UserSession NewSession(string hash = "hash-1") =>
        UserSession.Start(
            "sid-1", 1024,
            new DeviceDescriptor("dev-1", "iPhone 15 Pro", "IOS", "3.2.0", "203.0.113.7", "ua"),
            hash, Now, RefreshLifetime);

    [Fact]
    public void PresentingTheCurrentTokenRotatesIt()
    {
        var session = NewSession();

        var outcome = session.PresentRefreshToken("hash-1", "hash-2", Now.AddMinutes(5), RefreshLifetime);

        outcome.ShouldBe(RefreshOutcome.Rotated);
        session.IsActive.ShouldBeTrue();
        session.LastSeenAt.ShouldBe(Now.AddMinutes(5));
    }

    [Fact]
    public void PresentingARotatedTokenIsTreatedAsAReplayAndKillsTheChain()
    {
        var session = NewSession();
        session.PresentRefreshToken("hash-1", "hash-2", Now.AddMinutes(5), RefreshLifetime);

        // An attacker got hold of the token that was already rotated away.
        var outcome = session.PresentRefreshToken("hash-1", "hash-3", Now.AddMinutes(6), RefreshLifetime);

        outcome.ShouldBe(RefreshOutcome.Replayed);
        session.IsActive.ShouldBeFalse();
        session.RevokedBy.ShouldBe(RevocationReasons.TokenReplay);
        session.DomainEvents.OfType<RefreshTokenReplayDetected>().ShouldHaveSingleItem();
        session.DomainEvents.OfType<SessionRevoked>().ShouldHaveSingleItem();
    }

    [Fact]
    public void RotationDoesNotKeepTheOldHashOnTheAggregate()
    {
        var session = NewSession();
        session.PresentRefreshToken("hash-1", "hash-2", Now.AddMinutes(1), RefreshLifetime);

        session.CurrentRefreshTokenHash.ShouldBe("hash-2");
    }

    [Fact]
    public void AnExpiredTokenIsRefusedButIsNotTreatedAsALeak()
    {
        var session = NewSession();

        var outcome = session.PresentRefreshToken(
            "hash-1", "hash-2", Now.Add(RefreshLifetime).AddSeconds(1), RefreshLifetime);

        outcome.ShouldBe(RefreshOutcome.Expired);
        session.IsActive.ShouldBeTrue("expiry is the normal lifecycle and must not revoke the session");
    }

    [Fact]
    public void ARevokedSessionCannotBeBroughtBack()
    {
        var session = NewSession();
        session.Revoke(RevocationReasons.Self, Now);

        var outcome = session.PresentRefreshToken("hash-1", "hash-2", Now.AddMinutes(1), RefreshLifetime);

        outcome.ShouldBe(RefreshOutcome.Revoked);
        session.CurrentRefreshTokenHash.ShouldBeEmpty();
    }

    [Fact]
    public void RevokingTwiceIsIdempotentAndRaisesOneEvent()
    {
        var session = NewSession();

        session.Revoke(RevocationReasons.Self, Now);
        session.Revoke(RevocationReasons.Admin, Now.AddMinutes(1));

        session.DomainEvents.OfType<SessionRevoked>().ShouldHaveSingleItem();
        session.RevokedBy.ShouldBe(RevocationReasons.Self, "the first revocation carries the real reason");
    }
}
