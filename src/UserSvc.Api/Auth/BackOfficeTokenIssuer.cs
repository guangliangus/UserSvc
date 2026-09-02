using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using UserSvc.Api.Controllers.BackOffice;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.SignIn;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Features.Sessions;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Tenancy;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace UserSvc.Api.Auth;

/// <summary>
/// The back-office half of the token endpoint: the two private grants that turn a completed
/// sign-in, and a chosen tenant context, into credentials.
/// <para>
/// <b>Why the token endpoint at all, when the sign-in itself is a REST endpoint.</b> OpenIddict
/// owns token issuance in this service and the token endpoint is the only place it happens
/// (decision 10). A sign-in cannot mint there and answer ProblemDetails at the same time - the
/// token endpoint has to speak OAuth errors, or every OAuth client breaks - so the two halves are
/// split: <see cref="BackOfficeAuthController"/> judges the credential and answers with the tenant
/// list plus a signed ticket, and this class exchanges the ticket for the token the sign-in
/// decided on.
/// </para>
/// <para>
/// <b>How a pre-tenant token is expressed here.</b> The service being replaced minted a bespoke
/// JWT with <c>token_type=pre_tenant</c> and let a middleware allow-list two paths. This service
/// carries the same distinction as an OAuth <b>scope</b>, because OpenIddict already carries scopes
/// end to end - validated against the client's permissions, written into the access token, readable
/// by an ASP.NET Core policy - and the two policies the back office needs were written against
/// exactly that (see <see cref="BackOfficePolicies"/>). A sign-in with a context resolved is
/// granted <c>backoffice</c>; one still choosing is granted <c>backoffice_pre_tenant</c> and
/// nothing else, which reaches the two selection actions and no other route in the service.
/// </para>
/// <para>
/// The alternatives were rejected for concrete reasons. A bespoke claim would be trusted by
/// convention and wired by hand on every path. An audience answers "which resource server may
/// accept this", and there is one resource server here and two <i>stages of one session</i>. And
/// the absence of an <c>act</c> claim is not a mechanism at all: absence is also what a downgraded,
/// malformed or foreign token looks like, so a policy built on it fails open.
/// </para>
/// <para>
/// <b>The consumer/back-office guard cuts both ways.</b> The device grant refuses to grant a
/// back-office scope because its subject is a consumer id; these grants refuse a consumer token for
/// the same reason, from the other side - a back-office subject is an <c>iam.backend_users</c> id
/// and the two planes number their accounts independently.
/// </para>
/// </summary>
public sealed class BackOfficeTokenIssuer(
    BackOfficeSignInAppService signIns,
    SessionAppService sessions,
    IOpenIddictApplicationManager applications,
    IOpenIddictAuthorizationManager authorizations,
    IOptions<BackOfficeSignInOptions> options,
    ILogger<BackOfficeTokenIssuer> logger)
{
    /// <summary>
    /// Redeems the ticket a back-office sign-in produced. A private extension, so it carries our
    /// own URN: a bare name risks colliding with a grant type a future OAuth extension defines.
    /// </summary>
    public const string SignInGrantType = "urn:usersvc:params:oauth:grant-type:back-office";

    /// <summary>
    /// Exchanges a back-office access token plus a chosen context for a token that carries that
    /// context. It is the second half of a pre-tenant sign-in, and it is also how an established
    /// session switches context.
    /// </summary>
    public const string ContextGrantType = "urn:usersvc:params:oauth:grant-type:back-office-context";

    /// <summary>The <c>act</c> claim's wire shape: short keys, because it travels in every token.
    /// Written with the same names <see cref="BackOfficeCallerReader"/> reads.</summary>
    private static readonly JsonSerializerOptions ActJson = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Handles whichever of the two grants was asked for.
    /// </summary>
    /// <returns>A principal to sign in, or the OAuth error to answer with.</returns>
    public async Task<BackOfficeTokenResult> IssueAsync(
        HttpContext context,
        OpenIddictRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request);

        try
        {
            return string.Equals(request.GrantType, ContextGrantType, StringComparison.Ordinal)
                ? await ExchangeContextAsync(context, request, cancellationToken)
                : await RedeemSignInAsync(context, request, cancellationToken);
        }
        catch (AppException ex) when (ex.StatusCode is >= 400 and < 500)
        {
            // Everything the caller could have caused becomes one OAuth error. The specific reason
            // - unknown ticket, expired ticket, disabled account, a context this account may not
            // enter - goes to the log: at a token endpoint the difference between them is an oracle,
            // and the REST endpoints that a client is meant to discover it from say so properly.
            logger.LogInformation(
                ex,
                "A back-office token request was refused: {ErrorCode}.",
                ex.ErrorCode);

            return BackOfficeTokenResult.Rejected(
                OpenIddictConstants.Errors.InvalidGrant,
                "The back-office credential presented is not valid.");
        }
        catch (AppException ex)
        {
            // 5xx: this deployment cannot serve the grant - most often an unconfigured secret.
            // Reported as server_error rather than as invalid_grant, because an operator reading a
            // client's console needs to know it is not the credential's fault. That much was always
            // right; returning ex.Message with it was not.
            //
            // AppException messages are safe to return to the caller who caused them. The callers
            // here are anonymous - /connect/token takes no credential before this point - and the
            // messages on this path name internal configuration keys:
            // "BackOfficeSignIn:SignInTicketKey is unusable because it is not valid hex". That is a
            // free map of a deployment's secret names, handed to anybody who can POST a form. The
            // names are not values, and the intent - telling an operator to go and look at the
            // secrets - is worth keeping, so it moves to where only an operator reads it.
            //
            // The trace id is the join. It is computed exactly as the ProblemDetails contract
            // computes it (Program.cs: the bare 32-hex W3C trace id, not the full traceparent) and
            // it is what Serilog renders as {TraceId} on every line of this request, including the
            // Error line above - so the id a client pastes into a support ticket finds the log line
            // that still carries the whole message.
            var traceId = Activity.Current?.TraceId.ToString() ?? context.TraceIdentifier;

            logger.LogError(ex, "A back-office token request failed: {ErrorCode}.", ex.ErrorCode);

            return BackOfficeTokenResult.Rejected(
                OpenIddictConstants.Errors.ServerError,
                "This deployment cannot serve back-office token requests right now. It is a "
                + $"server-side fault rather than a problem with the credential presented. Quote trace id {traceId} "
                + "when reporting it.");
        }
    }

    /// <summary>
    /// Turns a sign-in ticket into either a pre-tenant token or a full one, according to what the
    /// sign-in decided. The client does not get to choose which.
    /// </summary>
    private async Task<BackOfficeTokenResult> RedeemSignInAsync(
        HttpContext context,
        OpenIddictRequest request,
        CancellationToken cancellationToken)
    {
        var ticket = (string?)request.GetParameter(Parameters.SignInTicket);
        if (string.IsNullOrWhiteSpace(ticket))
        {
            return BackOfficeTokenResult.Rejected(
                OpenIddictConstants.Errors.InvalidRequest,
                $"'{Parameters.SignInTicket}' is required.");
        }

        var grant = await signIns.RedeemAsync(ticket, cancellationToken);

        if (RefusedScope(request, grant) is { } refusal)
        {
            return refusal;
        }

        return await MintAsync(context, request, grant, cancellationToken);
    }

    /// <summary>
    /// Exchanges an existing back-office token for one carrying a chosen context.
    /// <para>
    /// The presented token is authenticated through the ordinary bearer scheme - the same
    /// validation every other endpoint in this service uses - so there is no second token-reading
    /// path to keep in step. It must carry one of the two back-office scopes, which is where a
    /// consumer token is refused: a C-end credential carries neither, so it cannot buy a
    /// back-office one here any more than the device grant can ask for a back-office scope.
    /// </para>
    /// <para>
    /// Everything about whether this account may enter this context - the membership, its status,
    /// the account's own status, the master data, the audit row - belongs to
    /// <c>BackOfficeContextAppService.SelectContextAsync</c>, which is the same code the REST
    /// context endpoint runs. This method contributes no guard of its own, deliberately: a second
    /// copy of that decision is a second thing to forget to update.
    /// </para>
    /// </summary>
    private async Task<BackOfficeTokenResult> ExchangeContextAsync(
        HttpContext context,
        OpenIddictRequest request,
        CancellationToken cancellationToken)
    {
        var authentication = await context.AuthenticateAsync(AuthenticationSchemes.Bearer);

        if (authentication.Principal is null || !HoldsBackOfficeScope(authentication.Principal))
        {
            logger.LogInformation(
                "A context exchange was refused: the request presented no back-office access token.");

            return BackOfficeTokenResult.Rejected(
                OpenIddictConstants.Errors.InsufficientScope,
                "This grant requires a back-office access token presented as a bearer token.");
        }

        var tenantType = (string?)request.GetParameter(Parameters.TenantType);
        var tenantCode = (string?)request.GetParameter(Parameters.TenantCode);

        if (string.IsNullOrWhiteSpace(tenantType) || string.IsNullOrWhiteSpace(tenantCode))
        {
            return BackOfficeTokenResult.Rejected(
                OpenIddictConstants.Errors.InvalidRequest,
                $"'{Parameters.TenantType}' and '{Parameters.TenantCode}' are required.");
        }

        var caller = BackOfficeCallerReader.Read(authentication.Principal);

        var grant = await signIns.SelectContextAsync(
            caller,
            new SelectTenantContextRequest { TenantType = tenantType, TenantCode = tenantCode },
            cancellationToken);

        var minted = await MintAsync(context, request, grant, cancellationToken);

        if (minted.Principal is not null)
        {
            await RetirePresentedSessionAsync(caller, cancellationToken);
        }

        return minted;
    }

    /// <summary>
    /// Takes down the session the caller presented, now that it holds a credential for the context
    /// it switched to.
    /// <para>
    /// <b>Without this a switch adds authority instead of moving it.</b> Measured before the fix:
    /// switching from company C001 to C002 on a second device left the C001 session ACTIVE, its
    /// access token answering <c>/back-office/me</c> with C001's scope envelope, and its refresh
    /// chain minting fresh C001 tokens - so an operator who "left" a tenant kept a working
    /// credential for it indefinitely, and revoking their access to C001 in the database was
    /// invisible to that chain until somebody signed the device out by hand. On the same device the
    /// partial unique index made the new session supersede the old one and hid the problem; the
    /// second device is where it showed.
    /// </para>
    /// <para>
    /// <b>After the mint, not before.</b> The failure mode of this order is "the old token lives a
    /// few more minutes"; of the other, "the operator holds nothing at all because the mint failed
    /// after their credential was destroyed". One <see cref="SessionAppService.RevokeDeviceAsync"/>
    /// does all three revocations in the load-bearing order - session row, OpenIddict chain, Redis
    /// revocation entry - so the old access token stops working now rather than at its expiry.
    /// </para>
    /// <para>
    /// <b>Best effort, with an Error log rather than a throw.</b> docs/architecture.md already
    /// settles this exact case for the superseding write, and by this point a good token has been
    /// minted: raising here would answer a successful exchange with a 502 and send the client back
    /// to mint another, leaving a second live session behind on every retry.
    /// </para>
    /// <para>
    /// <see cref="RevocationReasons.Superseded"/> rather than a new <c>CONTEXT_SWITCH</c> value:
    /// the row is a session stepping aside for a newer one, which is what that reason means, and
    /// adding a revocation reason is a change to a column's documented value set.
    /// </para>
    /// </summary>
    private async Task RetirePresentedSessionAsync(
        BackOfficeCaller caller, CancellationToken cancellationToken)
    {
        if (caller.SessionId.Length == 0)
        {
            // A pre-tenant credential carries no sid because it has no session row: this exchange
            // is the first context this sign-in has had, so there is nothing behind it to retire.
            return;
        }

        try
        {
            await sessions.RevokeDeviceAsync(
                SessionSubject.BackOffice(caller.UserId),
                caller.SessionId,
                RevocationReasons.Superseded,
                cancellationToken);
        }
        catch (AppException ex)
        {
            logger.LogError(
                ex,
                "A context exchange minted a token for back-office account {BackendUserId} but could "
                + "not retire the session {SessionId} it was switching away from; that session's "
                + "credential stays usable for its own context until it expires or is signed out.",
                caller.UserId,
                caller.SessionId);
        }
    }

    /// <summary>
    /// Assembles the principal OpenIddict signs in, creates the authorization every token in this
    /// chain hangs off, and - for a full token - opens the device session.
    /// <para>
    /// <b>The authorization is created before the session row</b>, because the session is the thing
    /// that has to remember the authorization id: a session without one cannot have its token chain
    /// revoked at sign-out. If the session insert then fails, the orphaned authorization carries no
    /// tokens and the pruning job clears it.
    /// </para>
    /// <para>
    /// <b>A pre-tenant token gets no session and no refresh token.</b> There is nothing to revoke -
    /// it lives five minutes, cannot be renewed, and reaches two endpoints - and creating a device
    /// session for an unfinished sign-in would put a row on the "signed-in devices" screen for a
    /// sign-in that never completed. The session is opened by the context exchange, which is the
    /// moment the sign-in actually finishes.
    /// </para>
    /// </summary>
    private async Task<BackOfficeTokenResult> MintAsync(
        HttpContext context,
        OpenIddictRequest request,
        BackOfficeTokenGrant grant,
        CancellationToken cancellationToken)
    {
        var application = await applications.FindByClientIdAsync(request.ClientId ?? string.Empty, cancellationToken);
        if (application is null)
        {
            return BackOfficeTokenResult.Rejected(
                OpenIddictConstants.Errors.InvalidClient, "The client application is not registered.");
        }

        var subject = grant.UserId.ToString(CultureInfo.InvariantCulture);
        var identity = new ClaimsIdentity(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);

        identity.SetClaim(Claims.Subject, subject);
        identity.SetClaim(Claims.Name, grant.ActorName);
        identity.SetClaim(
            BackOfficeCallerReader.TokenVersionClaimType,
            grant.TokenVersion.ToString(CultureInfo.InvariantCulture));

        if (grant.Act is { } act)
        {
            // The only computed thing that belongs in a back-office token. Roles, permissions,
            // menus and data scopes are recomputed per request and travel in response bodies, so a
            // permission taken away is gone on the next call rather than at the next sign-in.
            identity.SetClaim(BackOfficeCallerReader.ActClaimType, Serialize(act));
        }

        var deviceId = (string?)request.GetParameter(Parameters.DeviceId) ?? string.Empty;

        // Checked here rather than beside the session insert below, which is where it reads
        // naturally: everything from the authorization row onwards writes, and refusing after the
        // write would leave one orphaned ad-hoc authorization per malformed request - a table any
        // holder of one ticket could grow, cleared only by the pruning job.
        if (!grant.IsPreTenant && string.IsNullOrWhiteSpace(deviceId))
        {
            return BackOfficeTokenResult.Rejected(
                OpenIddictConstants.Errors.InvalidRequest,
                $"'{Parameters.DeviceId}' is required for a full back-office token.");
        }

        if (grant.IsPreTenant)
        {
            identity.SetScopes(BackOfficeScopes.PreTenant);

            // Overrides the service-wide access-token lifetime for this token only. An unfinished
            // sign-in has no business holding a ten-minute credential, and it has no refresh token
            // to renew one with either.
            identity.SetAccessTokenLifetime(options.Value.PreTenantTokenLifetime);
        }
        else
        {
            // offline_access is not decoration: OpenIddict issues a refresh token only when the
            // signed-in principal carries it, so without it this grant would mint an access token
            // and nothing to renew it with.
            identity.SetScopes(BackOfficeScopes.BackOffice, Scopes.OfflineAccess);
        }

        var authorization = await authorizations.CreateAsync(
            identity: identity,
            subject: subject,
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

        if (!grant.IsPreTenant)
        {
            var sessionId = Guid.CreateVersion7().ToString("n");
            identity.SetClaim(AuthenticationSchemes.SessionIdClaimType, sessionId);

            var device = new DeviceDescriptor(
                deviceId,
                (string?)request.GetParameter(Parameters.DeviceName) ?? string.Empty,
                (string?)request.GetParameter(Parameters.Platform) ?? string.Empty,
                (string?)request.GetParameter(Parameters.AppVersion) ?? string.Empty,
                context.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
                context.Request.Headers.UserAgent.ToString());

            // The same session concept consumer sign-in uses, on purpose: "sign this device out"
            // and the Redis revocation set have to work for an operator too, and a parallel
            // back-office session would be a second definition of what a session is. It also
            // supersedes the previous session on this device, which is what makes a context switch
            // leave no usable credential behind for the old context.
            await sessions.StartForBackOfficeAsync(
                grant.UserId, sessionId, authorizationId, device, cancellationToken);
        }

        identity.SetDestinations(Destination);

        return BackOfficeTokenResult.Granted(new ClaimsPrincipal(identity));
    }

    /// <summary>
    /// Refuses a client that asked for the back-office scope it is not getting.
    /// <para>
    /// Refusing rather than quietly granting the other one: a client that asked for
    /// <c>backoffice</c> and was handed a pre-tenant token would call a gated endpoint, be given a
    /// 403, and have nothing in either response to explain why. Silence about a downgrade is how
    /// that becomes a support ticket.
    /// </para>
    /// </summary>
    private static BackOfficeTokenResult? RefusedScope(OpenIddictRequest request, BackOfficeTokenGrant grant)
    {
        var granted = grant.IsPreTenant ? BackOfficeScopes.PreTenant : BackOfficeScopes.BackOffice;
        var requested = request.GetScopes();

        foreach (var scope in requested)
        {
            if ((scope == BackOfficeScopes.BackOffice || scope == BackOfficeScopes.PreTenant)
                && scope != granted)
            {
                return BackOfficeTokenResult.Rejected(
                    OpenIddictConstants.Errors.InvalidScope,
                    $"This sign-in grants '{granted}'. Ask for that scope or for none.");
            }
        }

        // An unfinished sign-in must not leave a long-lived credential behind, so asking for one is
        // refused rather than ignored.
        return grant.IsPreTenant && requested.Contains(Scopes.OfflineAccess)
            ? BackOfficeTokenResult.Rejected(
                OpenIddictConstants.Errors.InvalidScope,
                "A sign-in that has not chosen a context cannot be granted 'offline_access'. "
                + "Choose a context first.")
            : null;
    }

    /// <summary>
    /// Whether the presented principal is a back-office credential at all.
    /// <para>
    /// Both legal shapes of the scope claim are read - one claim per scope, and one
    /// space-delimited claim - for the same reason <see cref="BackOfficeAuthorization"/> reads
    /// both: a policy that understood one shape would refuse a perfectly good credential minted by
    /// an older build. The duplication is deliberate; that method is private to the policy and this
    /// one is not a policy.
    /// </para>
    /// </summary>
    private static bool HoldsBackOfficeScope(ClaimsPrincipal principal)
    {
        foreach (var claim in principal.FindAll(BackOfficeAuthorization.ScopeClaimType))
        {
            foreach (var granted in claim.Value.Split(
                         ' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (granted is BackOfficeScopes.BackOffice or BackOfficeScopes.PreTenant)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static string Serialize(ActClaim act) => JsonSerializer.Serialize(
        new ActClaimPayload(act.Type, act.Code, act.Dimension, act.IsAdmin), ActJson);

    /// <summary>
    /// Claims with no destination are dropped, which is the safe default. Four have to reach the
    /// access token: the subject and the session id for the same reasons the consumer grant needs
    /// them, and <c>act</c> plus <c>ver</c> because every back-office guard is a function of those
    /// two - a token that lost them on the way out would resolve to "holds nothing" for a caller
    /// who holds everything.
    /// </summary>
    private static IEnumerable<string> Destination(Claim claim) => claim.Type switch
    {
        Claims.Subject => [Destinations.AccessToken],
        Claims.Name => [Destinations.AccessToken],
        AuthenticationSchemes.SessionIdClaimType => [Destinations.AccessToken],
        BackOfficeCallerReader.ActClaimType => [Destinations.AccessToken],
        BackOfficeCallerReader.TokenVersionClaimType => [Destinations.AccessToken],
        _ => [],
    };

    /// <summary>Form parameters of the two back-office grants.</summary>
    private static class Parameters
    {
        public const string SignInTicket = "sign_in_ticket";
        public const string TenantType = "tenant_type";
        public const string TenantCode = "tenant_code";

        // The same four names the consumer device grant uses. They are spelled here rather than
        // shared because they are two separate wire contracts that happen to agree today; the
        // follow-ups note that promoting them to one type would be better than either copy.
        public const string DeviceId = "device_id";
        public const string DeviceName = "device_name";
        public const string Platform = "platform";
        public const string AppVersion = "app_version";
    }

    /// <summary>The act claim as it is written into a token.</summary>
    private sealed record ActClaimPayload(
        [property: System.Text.Json.Serialization.JsonPropertyName("type")] string Type,
        [property: System.Text.Json.Serialization.JsonPropertyName("code")] string Code,
        [property: System.Text.Json.Serialization.JsonPropertyName("dim")] string Dim,
        [property: System.Text.Json.Serialization.JsonPropertyName("is_admin")] bool IsAdmin);
}

/// <summary>
/// What the token endpoint should do about a back-office grant: sign this principal in, or answer
/// with this OAuth error.
/// <para>
/// It exists so the decision can be made outside <c>TokenController</c> while the controller keeps
/// the two things only a controller can do - <c>SignIn</c> and <c>Forbid</c> with OpenIddict's
/// authentication properties. The alternative, moving those calls in here, would need a
/// <c>ControllerBase</c> where there is none.
/// </para>
/// </summary>
/// <param name="Principal">The principal to sign in, or null when the grant was refused.</param>
/// <param name="Error">OAuth error code, when refused.</param>
/// <param name="ErrorDescription">
/// OAuth error description, when refused. Safe to return: it never names an account, never says
/// which of several refusals applied, and - since the caller of this endpoint is anonymous - never
/// names a configuration key. A server-side fault travels as a generic sentence plus the request's
/// trace id, which is the only thing that gets an operator to the log line holding the detail.
/// </param>
public sealed record BackOfficeTokenResult(
    ClaimsPrincipal? Principal, string Error = "", string ErrorDescription = "")
{
    public static BackOfficeTokenResult Granted(ClaimsPrincipal principal) => new(principal);

    public static BackOfficeTokenResult Rejected(string error, string description) =>
        new(null, error, description);
}
