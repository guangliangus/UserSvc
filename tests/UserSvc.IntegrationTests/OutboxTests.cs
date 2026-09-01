using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Auth;
using UserSvc.IntegrationTests.Infrastructure;
using UserSvc.Infrastructure.Persistence;

namespace UserSvc.IntegrationTests;

/// <summary>
/// Decision 16: the business row and its event row commit together or not at all. Presence of the
/// event proves nothing on its own - a second write after the first would look identical on the
/// happy path - so the atomicity is asserted from the failing side.
/// </summary>
public sealed class OutboxTests(ServiceFixture fixture) : IntegrationTest(fixture)
{
    [RequiresDockerFact]
    public async Task RevokingASessionCommitsItsDomainEventIntoTheOutboxAlongsideTheSessionRow()
    {
        var userId = await Fixture.SeedUserAsync();
        var sessionId = await SeedSessionAsync(userId, "device-a");

        await using (var scope = Fixture.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<UserSvcDbContext>();
            var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();

            var session = await db.UserSessions.SingleAsync(s => s.SessionId == sessionId);
            session.Revoke(RevocationReasons.Admin, DateTimeOffset.UtcNow);

            await unitOfWork.SaveChangesAsync(CancellationToken.None);
        }

        (await Fixture.QueryStringsAsync("SELECT event_name FROM identity.outbox_messages ORDER BY id"))
            .ShouldBe(
                ["user.session-revoked.v1"],
                "The wire name comes from [EventName] and is a published contract; a class rename "
                + "must never change it.");

        var payload = (await Fixture.QueryStringsAsync(
            "SELECT payload FROM identity.outbox_messages ORDER BY id")).Single();

        payload.Contains(sessionId, StringComparison.Ordinal)
            .ShouldBeTrue($"The event must identify the session it is about. Payload: {payload}");
        payload.Contains(RevocationReasons.Admin, StringComparison.Ordinal)
            .ShouldBeTrue($"The event must carry the revocation reason. Payload: {payload}");

        (await Fixture.QueryStringsAsync(
                "SELECT status FROM identity.user_sessions WHERE session_id = @p0", sessionId))
            .ShouldBe([SessionStatuses.Revoked]);
    }

    /// <summary>
    /// The atomicity proof. One <c>SaveChanges</c> carries the revocation, its outbox row, and an
    /// insert that violates <c>ix_user_sessions_session_id</c>. If the outbox were written outside
    /// the transaction - a second call, an interceptor after commit, a background flush - the event
    /// would survive a rollback and an event would exist for something that never happened.
    /// </summary>
    [RequiresDockerFact]
    public async Task ASaveThatFailsLeavesNeitherTheBusinessRowNorItsOutboxMessage()
    {
        var userId = await Fixture.SeedUserAsync();
        var sessionId = await SeedSessionAsync(userId, "device-a");

        await using (var scope = Fixture.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<UserSvcDbContext>();
            var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
            var now = DateTimeOffset.UtcNow;

            var session = await db.UserSessions.SingleAsync(s => s.SessionId == sessionId);
            session.Revoke(RevocationReasons.Admin, now);

            // A second row claiming the same sid violates the unique index on session_id, so the
            // whole unit of work has to roll back.
            db.UserSessions.Add(UserSession.Start(
                sessionId, userId, Device("device-b"), "authorization-b", now));

            var conflict = await Should.ThrowAsync<ConflictException>(
                async () => await unitOfWork.SaveChangesAsync(CancellationToken.None));

            conflict.ErrorCode.ShouldBe(ErrorCodes.Conflict);
        }

        (await Fixture.CountAsync("SELECT count(*) FROM identity.outbox_messages"))
            .ShouldBe(
                0,
                "The event row must share the failed transaction. An outbox message describing a "
                + "revocation that was rolled back is a lie published to every consumer.");

        (await Fixture.QueryStringsAsync(
                "SELECT status FROM identity.user_sessions WHERE session_id = @p0", sessionId))
            .ShouldBe([SessionStatuses.Active], "The revocation rolled back with everything else.");

        (await Fixture.CountAsync("SELECT count(*) FROM identity.user_sessions"))
            .ShouldBe(1, "The offending insert must not have survived either.");
    }

    private async Task<string> SeedSessionAsync(int userId, string deviceId)
    {
        var sessionId = Guid.CreateVersion7().ToString("n");

        await using var scope = Fixture.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<UserSvcDbContext>();

        db.UserSessions.Add(UserSession.Start(
            sessionId, userId, Device(deviceId), $"authorization-{deviceId}", DateTimeOffset.UtcNow));

        await db.SaveChangesAsync();
        return sessionId;
    }

    private static DeviceDescriptor Device(string deviceId) =>
        new(deviceId, "Test Device", "IOS", "1.0.0", "127.0.0.1", "integration-tests");
}
