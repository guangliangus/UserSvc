using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Sessions;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Users;
using UserSvc.IntegrationTests.Infrastructure;
using Xunit;

namespace UserSvc.IntegrationTests;

/// <summary>
/// The device grant, refresh rotation, replay detection and immediate sign-out, driven over HTTP
/// against the real OpenIddict server with its real PostgreSQL token store.
/// </summary>
public sealed class AuthFlowTests(ServiceFixture fixture) : IntegrationTest(fixture)
{
    private static readonly Uri SessionsPath = new("/api/v1/user/sessions", UriKind.Relative);

    [RequiresDockerFact]
    public async Task TheDeviceGrantMintsARefreshTokenAndAnAccessTokenCarryingSubAndSid()
    {
        var userId = await Fixture.SeedUserAsync();
        using var client = Fixture.CreateClient();

        var tokens = await TokenEndpoint.SignInDeviceAsync(client, userId, "device-a");

        tokens.Status.ShouldBe(HttpStatusCode.OK, $"The token endpoint answered: {tokens.Error} {tokens.ErrorDescription}");
        tokens.AccessToken.ShouldNotBeNullOrEmpty();
        tokens.RefreshToken.ShouldNotBeNullOrEmpty(
            "Without offline_access on the signed-in principal OpenIddict mints an access token and "
            + "nothing to renew it with, and the whole session design collapses.");

        JwtClaims.Subject(tokens.AccessToken).ShouldBe(
            userId.ToString(CultureInfo.InvariantCulture),
            "sub must reach the access token or no downstream service knows who is calling.");

        var sessionId = JwtClaims.SessionId(tokens.AccessToken);
        sessionId.ShouldNotBeNullOrEmpty(
            "sid must reach the access token or the revocation set can never be consulted; claims "
            + "with no destination are silently dropped by OpenIddict.");

        var stored = await SessionAsync(sessionId);
        stored.ShouldNotBeNull("The grant must have written the session row the sid names.");
        stored.Value.Status.ShouldBe(SessionStatuses.Active);
    }

    /// <summary>
    /// The consumer plane and the back-office plane number their accounts independently, and this
    /// grant authenticates the consumer one. Before it was checked, a device login that simply added
    /// <c>scope=backoffice</c> to the form came back with a token that answered
    /// <c>GET /api/v1/user/profile</c> as consumer <c>N</c> and <c>GET /api/v1/auth/tenants</c> with
    /// back-office account <c>N</c>'s tenant memberships - one credential, two different people.
    /// </summary>
    [RequiresDockerTheory]
    [InlineData("backoffice")]
    [InlineData("backoffice_pre_tenant")]
    [InlineData("openid backoffice")]
    public async Task TheDeviceGrantRefusesToMintABackOfficeScope(string scope)
    {
        var userId = await Fixture.SeedUserAsync();
        using var client = Fixture.CreateClient();

        var tokens = await TokenEndpoint.SignInDeviceAsync(client, userId, "device-a", scope: scope);

        tokens.Error.ShouldBe(
            "invalid_scope",
            "A client asking a consumer grant for a back-office scope is confused about which plane "
            + "it is on, and must be told so rather than quietly handed a narrower token.");
        tokens.AccessToken.ShouldBeEmpty();
    }

    [RequiresDockerFact]
    public async Task RefreshingRotatesTheTokenPairWhileKeepingTheSameSessionId()
    {
        var userId = await Fixture.SeedUserAsync();
        using var client = Fixture.CreateClient();

        var first = await TokenEndpoint.SignInDeviceAsync(client, userId, "device-a");
        var second = await TokenEndpoint.RefreshAsync(client, first.RefreshToken);

        second.Status.ShouldBe(HttpStatusCode.OK, $"Refresh failed: {second.Error} {second.ErrorDescription}");
        second.RefreshToken.ShouldNotBe(
            first.RefreshToken,
            "Refresh tokens are single use; handing the same one back would make replay detection meaningless.");
        second.AccessToken.ShouldNotBe(first.AccessToken);

        JwtClaims.SessionId(second.AccessToken).ShouldBe(
            JwtClaims.SessionId(first.AccessToken),
            "The rotated pair belongs to the same device session, so sid must be carried over - "
            + "a new sid would orphan the session row and make sign-out unable to find it.");
    }

    /// <summary>
    /// The 400 alone is worthless as an assertion: OpenIddict answers a redeemed refresh token with
    /// <c>invalid_grant</c> whether or not our replay handler ever ran. What proves the handler ran
    /// is the side effects - the session flipped to REVOKED with reason TOKEN_REPLAY, and both
    /// domain events in the outbox. Delete the handler and only those assertions fail.
    /// </summary>
    [RequiresDockerFact]
    public async Task ReplayingARedeemedRefreshTokenIsRefusedAndTakesTheSessionDownWithReasonTokenReplay()
    {
        var userId = await Fixture.SeedUserAsync();
        using var client = Fixture.CreateClient();

        var first = await TokenEndpoint.SignInDeviceAsync(client, userId, "device-a");
        var sessionId = JwtClaims.SessionId(first.AccessToken);

        var rotated = await TokenEndpoint.RefreshAsync(client, first.RefreshToken);
        rotated.Status.ShouldBe(HttpStatusCode.OK);

        var replay = await TokenEndpoint.RefreshAsync(client, first.RefreshToken);

        replay.Status.ShouldBe(HttpStatusCode.BadRequest);
        replay.Error.ShouldBe(
            "invalid_grant",
            "SetRefreshTokenReuseLeeway(TimeSpan.Zero) is what makes this a refusal; the 30-second "
            + "default would have accepted the replay and answered 200.");

        var session = await SessionAsync(sessionId);
        session.ShouldNotBeNull();
        session.Value.Status.ShouldBe(
            SessionStatuses.Revoked,
            "A replayed refresh token means the token leaked, so the session must not survive it.");
        session.Value.RevokedBy.ShouldBe(
            RevocationReasons.TokenReplay,
            "The reason is what an audit distinguishes a leak from an ordinary sign-out by.");

        var events = await Fixture.QueryStringsAsync(
            "SELECT event_name FROM identity.outbox_messages ORDER BY id");

        events.ShouldContain(
            "user.refresh-token-replayed.v1",
            "The security alert is the reason this handler exists. Without it a leak is refused "
            + "silently and nobody is ever told.");
        events.ShouldContain("user.session-revoked.v1");
    }

    [RequiresDockerFact]
    public async Task AReplayKillsTheWholeChainSoTheLegitimatelyRotatedRefreshTokenDiesToo()
    {
        var userId = await Fixture.SeedUserAsync();
        using var client = Fixture.CreateClient();

        var first = await TokenEndpoint.SignInDeviceAsync(client, userId, "device-a");
        var rotated = await TokenEndpoint.RefreshAsync(client, first.RefreshToken);
        rotated.Status.ShouldBe(HttpStatusCode.OK);

        var replay = await TokenEndpoint.RefreshAsync(client, first.RefreshToken);
        replay.Status.ShouldBe(HttpStatusCode.BadRequest);

        var afterReplay = await TokenEndpoint.RefreshAsync(client, rotated.RefreshToken);

        afterReplay.Status.ShouldBe(
            HttpStatusCode.BadRequest,
            "A leak means the whole chain is suspect. Leaving the honest device's token alive would "
            + "let whichever party rotated last keep the session.");
        afterReplay.Error.ShouldBe("invalid_grant");
        afterReplay.AccessToken.ShouldBeEmpty();
    }

    /// <summary>
    /// The promise decision 11 makes: signing a device out stops it at once, not at token expiry.
    /// The Redis TTL is asserted too, because it is the only thing keeping the revocation set from
    /// growing without bound.
    /// </summary>
    [RequiresDockerFact]
    public async Task SigningADeviceOutStopsItsStillUnexpiredAccessTokenOnTheVeryNextRequest()
    {
        var userId = await Fixture.SeedUserAsync();
        using var anonymous = Fixture.CreateClient();

        var tokens = await TokenEndpoint.SignInDeviceAsync(anonymous, userId, "device-a");
        var sessionId = JwtClaims.SessionId(tokens.AccessToken);

        using var device = Fixture.CreateClient();
        device.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        using (var beforeSignOut = await device.GetAsync(SessionsPath))
        {
            beforeSignOut.StatusCode.ShouldBe(
                HttpStatusCode.OK, "The freshly minted access token must be accepted.");
        }

        using (var signOut = await device.DeleteAsync(
                   new Uri($"/api/v1/user/sessions/{sessionId}", UriKind.Relative)))
        {
            signOut.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        }

        using var afterSignOut = await device.GetAsync(SessionsPath);

        afterSignOut.StatusCode.ShouldBe(
            HttpStatusCode.Unauthorized,
            "The token is still signed and unexpired, so only the revocation set can refuse it. "
            + "A sign-out that takes effect ten minutes later is not the feature anyone asked for.");

        var problem = await ProblemDetailsBody.ReadAsync(afterSignOut);
        problem.ContentType.ShouldBe("application/problem+json");
        problem.ErrorCode.ShouldBe(
            ErrorCodes.SessionRevoked,
            "A generic UNAUTHORIZED would tell the client to retry the same token; SESSION_REVOKED "
            + "tells it to sign in again.");

        var lifetime = Fixture.Services
            .GetRequiredService<IOptions<AuthSessionOptions>>().Value.AccessTokenLifetime;

        var ttl = await Fixture.RedisProbe.GetDatabase()
            .KeyTimeToLiveAsync($"{UserSvcApplicationFactory.RedisKeyPrefix}revoked:sid:{sessionId}");

        ttl.ShouldNotBeNull(
            "Either the revocation key is missing or it has no expiry. Without a TTL the revocation "
            + "set grows for ever; without the key the sign-out is not enforced at all.");
        ttl.Value.ShouldBeLessThanOrEqualTo(lifetime);
        ttl.Value.ShouldBeGreaterThan(
            lifetime - TimeSpan.FromMinutes(1),
            "The TTL must track the access-token lifetime. A shorter one resurrects revoked tokens "
            + "for the difference.");
    }

    [RequiresDockerFact]
    public async Task ARefreshTokenWhoseSessionWasSignedOutIsRefusedEvenThoughTheTokenItselfIsIntact()
    {
        var userId = await Fixture.SeedUserAsync();
        using var anonymous = Fixture.CreateClient();

        var tokens = await TokenEndpoint.SignInDeviceAsync(anonymous, userId, "device-a");
        var sessionId = JwtClaims.SessionId(tokens.AccessToken);

        using var device = Fixture.CreateClient();
        device.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        using (var signOut = await device.DeleteAsync(
                   new Uri($"/api/v1/user/sessions/{sessionId}", UriKind.Relative)))
        {
            signOut.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        }

        var refresh = await TokenEndpoint.RefreshAsync(anonymous, tokens.RefreshToken);

        refresh.Status.ShouldBe(
            HttpStatusCode.BadRequest,
            "Sign-out must kill the refresh chain in the same second, not whenever the revocation "
            + "happens to be observed.");
        refresh.Error.ShouldBe("invalid_grant");
    }

    [RequiresDockerFact]
    public async Task TheDeviceGrantRefusesAnUnknownUserWithAnOAuthErrorRatherThanProblemDetails()
    {
        using var client = Fixture.CreateClient();

        var tokens = await TokenEndpoint.SignInDeviceAsync(client, userId: 987654, deviceId: "device-a");

        tokens.Status.ShouldBe(HttpStatusCode.BadRequest);
        tokens.Error.ShouldBe(
            "invalid_grant",
            "A 404 for 'no such user' beside a 403 for 'disabled' would make the token endpoint a "
            + "user-enumeration oracle; one indistinguishable invalid_grant goes out instead.");
    }

    [RequiresDockerFact]
    public async Task TheDeviceGrantRefusesADisabledAccountWithTheSameAnswerAsAnUnknownOne()
    {
        var userId = await Fixture.SeedUserAsync(UserStatuses.Disabled);
        using var client = Fixture.CreateClient();

        var tokens = await TokenEndpoint.SignInDeviceAsync(client, userId, "device-a");

        tokens.Status.ShouldBe(HttpStatusCode.BadRequest);
        tokens.Error.ShouldBe("invalid_grant");

        (await Fixture.CountAsync("SELECT count(*) FROM identity.user_sessions"))
            .ShouldBe(0, "A refused sign-in must leave no session row behind.");
    }

    private async Task<(string Status, string RevokedBy)?> SessionAsync(string sessionId)
    {
        var rows = await Fixture.QueryStringsAsync(
            "SELECT status || '|' || revoked_by FROM identity.user_sessions WHERE session_id = @p0",
            sessionId);

        if (rows.Count == 0)
        {
            return null;
        }

        var parts = rows[0].Split('|');
        return (parts[0], parts[1]);
    }
}
