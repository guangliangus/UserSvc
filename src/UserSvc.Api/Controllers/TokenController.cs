using System.Globalization;
using System.Security.Claims;
using Asp.Versioning;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using UserSvc.Api.Auth;
using UserSvc.Api.Controllers.BackOffice;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Sessions;
using UserSvc.Domain.Auth;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace UserSvc.Api.Controllers;

/// <summary>
/// The OAuth 2.0 token endpoint (decision 10). It is <b>not</b> a REST resource: the request and
/// response shapes are RFC 6749's, so it is version-neutral and it answers failures with OAuth
/// error objects rather than the ProblemDetails contract of decision 09. Two grants live here —
/// <c>refresh_token</c>, and one private device-login grant.
/// <para>
/// By the time <see cref="Exchange"/> runs, OpenIddict has already validated the client and the
/// grant. That is also why replay detection is not here but in
/// <see cref="RefreshTokenReplayHandler"/>: a replayed refresh token is rejected before this action
/// is ever reached.
/// </para>
/// </summary>
[ApiController]
[ApiVersionNeutral]
[Route(TokenEndpointPath)]
[Produces("application/json")]
public sealed class TokenController(
    SessionAppService sessions,
    IOpenIddictApplicationManager applications,
    IOpenIddictAuthorizationManager authorizations,
    IOptions<AuthTokenOptions> options,
    ILogger<TokenController> logger) : ControllerBase
{
    /// <summary>The route and the value handed to <c>SetTokenEndpointUris</c> are the same constant
    /// on purpose: two copies that drift produce a 404 with no other symptom.</summary>
    public const string TokenEndpointPath = "/connect/token";

    private readonly AuthTokenOptions _options = options.Value;

    [HttpPost]
    [Consumes("application/x-www-form-urlencoded")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Exchange(CancellationToken cancellationToken)
    {
        var request = HttpContext.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException(
                          "The OpenIddict server request could not be read. The route of this action " +
                          "and SetTokenEndpointUris must be the same path.");

        if (request.IsRefreshTokenGrantType())
        {
            return await RefreshAsync(cancellationToken);
        }

        if (string.Equals(request.GrantType, _options.DeviceGrantType, StringComparison.Ordinal))
        {
            return await DeviceLoginAsync(request, cancellationToken);
        }

        // OpenIddict rejects unregistered grant types before this point; reaching here means one was
        // allowed on the server but never wired up.
        return Reject(
            OpenIddictConstants.Errors.UnsupportedGrantType,
            "The specified grant type is not supported by this endpoint.");
    }

    /// <summary>
    /// Rotate the refresh chain. OpenIddict has already proved the token is genuine, unexpired and
    /// unredeemed; what is left is the check it cannot make — whether the session the token belongs
    /// to has since been signed out. Doing it here is what makes a device sign-out effective
    /// immediately, without waiting for the chain revocation to be observed.
    /// </summary>
    private async Task<IActionResult> RefreshAsync(CancellationToken cancellationToken)
    {
        var result = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        if (result.Principal is null)
        {
            return Reject(OpenIddictConstants.Errors.InvalidGrant, "The refresh token is not valid.");
        }

        var sessionId = result.Principal.GetClaim(AuthenticationSchemes.SessionIdClaimType);
        if (string.IsNullOrEmpty(sessionId) || !await sessions.TryTouchAsync(sessionId, cancellationToken))
        {
            return Reject(OpenIddictConstants.Errors.InvalidGrant, "The session this refresh token belongs to is no longer active.");
        }

        // Carrying the claims over verbatim keeps sid - and the authorization id OpenIddict tracks
        // internally - attached to the new pair, so the chain stays one chain.
        var identity = new ClaimsIdentity(
            result.Principal.Claims,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            Claims.Name,
            Claims.Role);

        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// Password-less device login. The authorization is created <b>before</b> the session row,
    /// because the session is the thing that has to remember the authorization id — a session
    /// without one cannot have its token chain revoked on sign-out. If the session insert then
    /// fails, the orphaned authorization carries no tokens and the pruning job clears it.
    /// <para>
    /// The application layer refuses an unknown or disabled user by throwing, and that throw is
    /// caught here rather than allowed to reach <c>AppExceptionHandler</c>: a token endpoint that
    /// answers ProblemDetails breaks every OAuth client, and a 404 for "no such user" next to a 403
    /// for "disabled" would make this a user-enumeration oracle. One <c>invalid_grant</c> goes out,
    /// the real reason goes to the log.
    /// </para>
    /// </summary>
    private async Task<IActionResult> DeviceLoginAsync(
        OpenIddictRequest request,
        CancellationToken cancellationToken)
    {
        var subject = (string?)request.GetParameter(DeviceLoginParameters.UserId);
        if (!int.TryParse(subject, CultureInfo.InvariantCulture, out var userId) || userId <= 0)
        {
            return Reject(OpenIddictConstants.Errors.InvalidRequest, $"'{DeviceLoginParameters.UserId}' is required and must be a positive integer.");
        }

        var deviceId = (string?)request.GetParameter(DeviceLoginParameters.DeviceId);
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return Reject(OpenIddictConstants.Errors.InvalidRequest, $"'{DeviceLoginParameters.DeviceId}' is required.");
        }

        var application = await applications.FindByClientIdAsync(request.ClientId ?? string.Empty, cancellationToken);
        if (application is null)
        {
            return Reject(OpenIddictConstants.Errors.InvalidClient, "The client application is not registered.");
        }

        // This grant authenticates a CONSUMER identity - the subject below is an identity.users id -
        // and the back-office scopes describe a back-office one, whose subject is an
        // iam.backend_users id. The two planes number their accounts independently, so a token that
        // carried both would be read as two different people by two halves of this service.
        // Measured before this check existed: a device login for consumer 2 that simply asked for
        // scope=backoffice came back with a token that answered GET /api/v1/user/profile as consumer
        // 2 AND GET /api/v1/auth/tenants with back-office account 2's tenant memberships. Refusing
        // rather than quietly dropping the scope, because a client that asked for this is confused
        // about which plane it is on and should be told so.
        var backOfficeScopes = request.GetScopes()
            .Where(scope => scope == BackOfficeScopes.BackOffice || scope == BackOfficeScopes.PreTenant)
            .ToList();

        if (backOfficeScopes.Count > 0)
        {
            return Reject(
                OpenIddictConstants.Errors.InvalidScope,
                "The device login grant issues consumer credentials and cannot grant a back-office scope.");
        }

        var sessionId = Guid.CreateVersion7().ToString("n");
        var identity = new ClaimsIdentity(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);

        identity.SetClaim(Claims.Subject, userId.ToString(CultureInfo.InvariantCulture));
        identity.SetClaim(AuthenticationSchemes.SessionIdClaimType, sessionId);

        // offline_access is not optional decoration: OpenIddict issues a refresh token only when the
        // signed-in principal carries it, so without it this grant would mint an access token and
        // nothing to renew it with.
        identity.SetScopes([Scopes.OfflineAccess, .. request.GetScopes()]);

        var authorization = await authorizations.CreateAsync(
            identity: identity,
            subject: userId.ToString(CultureInfo.InvariantCulture),
            client: await applications.GetIdAsync(application, cancellationToken) ?? string.Empty,
            type: AuthorizationTypes.AdHoc,
            scopes: identity.GetScopes(),
            cancellationToken: cancellationToken);

        var authorizationId = await authorizations.GetIdAsync(authorization, cancellationToken);
        if (string.IsNullOrEmpty(authorizationId))
        {
            throw new InvalidOperationException("The OpenIddict authorization was created without an identifier.");
        }

        identity.SetAuthorizationId(authorizationId);

        var device = new DeviceDescriptor(
            deviceId,
            (string?)request.GetParameter(DeviceLoginParameters.DeviceName) ?? string.Empty,
            (string?)request.GetParameter(DeviceLoginParameters.Platform) ?? string.Empty,
            (string?)request.GetParameter(DeviceLoginParameters.AppVersion) ?? string.Empty,
            HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            Request.Headers.UserAgent.ToString());

        try
        {
            await sessions.StartAsync(userId, sessionId, authorizationId, device, cancellationToken);
        }
        catch (AppException ex)
        {
            logger.LogWarning(
                ex, "Device login refused for user {UserId}: {ErrorCode}.", userId, ex.ErrorCode);

            return Reject(
                OpenIddictConstants.Errors.InvalidGrant, "The device login was refused.");
        }

        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// A failure here must be an OAuth error object, not ProblemDetails: every OAuth client on earth
    /// parses <c>error</c> / <c>error_description</c> from the token endpoint. Forbidding with these
    /// properties is how OpenIddict is told to write one.
    /// </summary>
    private ForbidResult Reject(string error, string description) => Forbid(
        new AuthenticationProperties(new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        }),
        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

    /// <summary>
    /// Claims with no destination are dropped, which is the safe default. <c>sid</c> has to reach the
    /// access token or nothing downstream can consult the revocation set (decision 11).
    /// </summary>
    private static IEnumerable<string> GetDestinations(Claim claim) => claim.Type switch
    {
        Claims.Subject => [Destinations.AccessToken],
        AuthenticationSchemes.SessionIdClaimType => [Destinations.AccessToken],
        _ => [],
    };

    /// <summary>Form parameters of the private device-login grant.</summary>
    private static class DeviceLoginParameters
    {
        public const string UserId = "user_id";
        public const string DeviceId = "device_id";
        public const string DeviceName = "device_name";
        public const string Platform = "platform";
        public const string AppVersion = "app_version";
    }
}
