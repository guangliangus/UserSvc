using System.Net;
using Shouldly;
using UserSvc.Domain.Auth;
using UserSvc.IntegrationTests.Infrastructure;

namespace UserSvc.IntegrationTests;

/// <summary>
/// The two rules that decide which sessions survive a sign-in. Both are asserted on the stored
/// revocation reason rather than on a row count: the counts are identical whichever rule fired,
/// and the reason is what the "signed-in devices" screen and the audit trail actually read.
/// </summary>
public sealed class DeviceSessionTests(ServiceFixture fixture) : IntegrationTest(fixture)
{
    [RequiresDockerFact]
    public async Task ASecondSignInFromTheSameDeviceSupersedesThePreviousSessionInsteadOfSittingBesideIt()
    {
        var userId = await Fixture.SeedUserAsync();
        using var client = Fixture.CreateClient();

        var first = await TokenEndpoint.SignInDeviceAsync(client, userId, "device-a");
        var second = await TokenEndpoint.SignInDeviceAsync(client, userId, "device-a");

        second.Status.ShouldBe(
            HttpStatusCode.OK,
            "Signing in again on a known device must succeed. The partial unique index on "
            + $"(user_id, device_id) WHERE status = 'ACTIVE' would otherwise refuse the insert: {second.ErrorDescription}");

        var previous = await SessionAsync(first.SessionId);
        previous.Status.ShouldBe(SessionStatuses.Revoked);
        previous.RevokedBy.ShouldBe(
            RevocationReasons.Superseded,
            "The old session stepped aside for the same device; it was not evicted by the cap and "
            + "the user did not sign it out.");

        (await SessionAsync(second.SessionId)).Status.ShouldBe(SessionStatuses.Active);

        (await Fixture.CountAsync(
                "SELECT count(*) FROM identity.user_sessions WHERE user_id = @p0 AND status = @p1",
                userId, SessionStatuses.Active))
            .ShouldBe(1, "One user on one device may hold at most one active session.");
    }

    [RequiresDockerFact]
    public async Task ReachingTheActiveDeviceCapRevokesTheLeastRecentlySeenSessionWithReasonDeviceLimit()
    {
        UserSvcApplicationFactory.MaxActiveDevices.ShouldBe(
            2, "This test signs in three devices and expects exactly one eviction.");

        var userId = await Fixture.SeedUserAsync();
        using var client = Fixture.CreateClient();

        var oldest = await TokenEndpoint.SignInDeviceAsync(client, userId, "device-a");
        var middle = await TokenEndpoint.SignInDeviceAsync(client, userId, "device-b");

        // Refreshing touches last_seen_at, so "least recently seen" is decided by an actual event
        // rather than by two creation timestamps a millisecond apart.
        var refreshed = await TokenEndpoint.RefreshAsync(client, middle.RefreshToken);
        refreshed.Status.ShouldBe(HttpStatusCode.OK);

        var newest = await TokenEndpoint.SignInDeviceAsync(client, userId, "device-c");
        newest.Status.ShouldBe(HttpStatusCode.OK);

        var evicted = await SessionAsync(oldest.SessionId);
        evicted.Status.ShouldBe(SessionStatuses.Revoked);
        evicted.RevokedBy.ShouldBe(
            RevocationReasons.DeviceLimit,
            "device-a was the least recently seen, so it is the one that gives way. SUPERSEDED here "
            + "would mean the cap fired on the wrong rule.");

        (await SessionAsync(middle.SessionId)).Status.ShouldBe(
            SessionStatuses.Active, "device-b was refreshed most recently and must survive.");
        (await SessionAsync(newest.SessionId)).Status.ShouldBe(SessionStatuses.Active);

        (await Fixture.CountAsync(
                "SELECT count(*) FROM identity.user_sessions WHERE user_id = @p0 AND status = @p1",
                userId, SessionStatuses.Active))
            .ShouldBe(UserSvcApplicationFactory.MaxActiveDevices);
    }

    [RequiresDockerFact]
    public async Task SigningOutASessionThatBelongsToSomebodyElseAnswers404RatherThan403()
    {
        var owner = await Fixture.SeedUserAsync();
        var stranger = await Fixture.SeedUserAsync();

        using var client = Fixture.CreateClient();
        var tokens = await TokenEndpoint.SignInDeviceAsync(client, owner, "device-a");

        using var strangerClient = Fixture.CreateDevClient(stranger);
        using var response = await strangerClient.DeleteAsync(
            new Uri($"/api/v1/user/sessions/{tokens.SessionId}", UriKind.Relative));

        response.StatusCode.ShouldBe(
            HttpStatusCode.NotFound,
            "403 here would let a caller probe whether a session id exists; the status difference "
            + "is the oracle.");

        (await SessionAsync(tokens.SessionId)).Status.ShouldBe(
            SessionStatuses.Active, "The refused request must not have revoked anything.");
    }

    private async Task<(string Status, string RevokedBy)> SessionAsync(string sessionId)
    {
        var rows = await Fixture.QueryStringsAsync(
            "SELECT status || '|' || revoked_by FROM identity.user_sessions WHERE session_id = @p0",
            sessionId);

        rows.Count.ShouldBe(1, $"Expected exactly one session row for sid '{sessionId}'.");

        var parts = rows[0].Split('|');
        return (parts[0], parts[1]);
    }
}
