using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Api.Auth;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Api.Controllers.BackOffice;

/// <summary>
/// Choosing and reading the back-office tenant context.
/// <para>
/// Two of these three actions accept a token that has not chosen a context yet; the third needs a
/// chosen one but deliberately needs no permission. See <see cref="BackOfficePolicies"/> for how a
/// pre-tenant token is expressed here, and <see cref="Me"/> for why it carries no permission
/// requirement.
/// </para>
/// </summary>
[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/back-office")]
[Produces("application/json")]
public sealed class TenantContextController(BackOfficeContextAppService contexts) : ControllerBase
{
    /// <summary>
    /// The contexts this session may enter. Answers for a pre-tenant token too - it is what the
    /// chooser screen is built from.
    /// </summary>
    [HttpGet("tenants")]
    [Authorize(Policy = BackOfficePolicies.TenantSelection)]
    [ProducesResponseType<TenantListResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public Task<TenantListResponse> ListTenants(CancellationToken cancellationToken) =>
        contexts.ListTenantsAsync(BackOfficeCallerReader.Read(User), cancellationToken);

    /// <summary>
    /// Enter a context - the first choice after signing in, or a later switch.
    /// <para>
    /// It answers with the authority surface of the chosen context and does <b>not</b> mint tokens:
    /// credentials come out of the OpenIddict token endpoint, and the exchange that turns this
    /// decision into a full back-office token is described in <see cref="BackOfficePolicies"/>.
    /// That split is also why this action retires no credential of its own: the caller's current
    /// token is what it must present to that exchange, so killing it here would end every switch
    /// in a forced sign-in. The old credential is retired at the moment the new one is minted -
    /// see the context grant.
    /// </para>
    /// <para>
    /// <b>A tenant the caller does not hold answers 403, not the 400 porting spec 09 section 3.3
    /// reads as.</b> The reasoning is written out on
    /// <see cref="BackOfficeContextAppService.SelectContextAsync"/>, and the short version is that
    /// the spec's "BadRequest" was an error <i>kind</i> that went out as HTTP 200, so there is no
    /// 400 to preserve - while TENANT_NOT_AUTHORIZED already means 403 on every gated route in
    /// this service.
    /// </para>
    /// </summary>
    /// <response code="200">The chosen context, with the authority surface it resolves to.</response>
    /// <response code="400">BAD_REQUEST - the tenant type is neither company nor supplier.</response>
    /// <response code="401">The token is not usable, or ACCOUNT_DISABLED.</response>
    /// <response code="403">TENANT_NOT_AUTHORIZED or TENANT_DISABLED - this account may not enter
    /// this tenant, and no correction to the request changes that.</response>
    /// <response code="409">TENANT_INACTIVE - the tenant is switched off in the master data.</response>
    [HttpPost("context")]
    [Authorize(Policy = BackOfficePolicies.TenantSelection)]
    [ProducesResponseType<TenantContextResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public Task<TenantContextResponse> SelectContext(
        SelectTenantContextRequest request, CancellationToken cancellationToken) =>
        contexts.SelectContextAsync(BackOfficeCallerReader.Read(User), request, cancellationToken);

    /// <summary>
    /// The signed-in user's own context: who they are, where they are acting, and what they may do.
    /// <para>
    /// <b>There is deliberately no permission requirement on this action, and that is not an
    /// oversight.</b> Every other back-office route is gated on a permission code, and this one
    /// cannot be: the shell calls it before it can render anything, and the caller who needs it
    /// most is a member who was just added and has been granted no menus and no permissions at all.
    /// Gate it, and that person gets a 403 in place of the screen that would tell them their
    /// administrator has not finished setting them up - while an administrator looking at the same
    /// account sees a correctly configured member. The response carries only facts about the caller
    /// themselves, so authentication is the whole boundary here.
    /// </para>
    /// </summary>
    [HttpGet("me")]
    [Authorize(Policy = BackOfficePolicies.BackOffice)]
    [ProducesResponseType<BackOfficeMeResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public Task<BackOfficeMeResponse> Me(CancellationToken cancellationToken) =>
        contexts.GetMeAsync(BackOfficeCallerReader.Read(User), cancellationToken);
}

/// <summary>
/// Authorization policies for the back office, and the token shape behind them.
/// <para>
/// <b>How a pre-tenant token expresses itself here.</b> The Go service this replaces minted a
/// bespoke token with <c>token_type=pre_tenant</c> and let a middleware allow-list two paths. This
/// service issues tokens through OpenIddict, so the same distinction is carried by a
/// <b>scope</b>: a session that has not chosen a context yet is granted
/// <see cref="BackOfficeScopes.PreTenant"/> and nothing else, and a session that has is granted
/// <see cref="BackOfficeScopes.BackOffice"/>.
/// </para>
/// <para>
/// A scope rather than a claim or an audience, for three reasons. OpenIddict already carries scopes
/// end to end - they are validated against the client's permissions, they land in the access
/// token, and ASP.NET Core policies can read them - whereas a bespoke claim would be trusted by
/// convention and wired by hand. An audience answers "which resource server may accept this",
/// and there is exactly one resource server here and two <i>stages of one session</i>, so an
/// audience would encode the wrong distinction and pass silently anywhere it was not checked. And
/// the absence of an <c>act</c> claim is not a mechanism at all: absence is also what a downgraded
/// or malformed token looks like, and a policy that treats absence as permission fails open.
/// </para>
/// <para>
/// The consumer-facing guard falls out of the same mechanism at no extra cost: a C-end token
/// carries neither scope, so both policies refuse it with a 403 rather than letting it wander into
/// the back office.
/// </para>
/// <para>
/// Registering these policies, and granting the two scopes at the token endpoint, are host
/// concerns that live in files this slice does not own - see the deployment notes that accompany
/// it. A pre-tenant token must additionally be short lived and must <b>not</b> carry
/// <c>offline_access</c>: an unfinished sign-in has no business leaving a long-lived credential
/// behind.
/// </para>
/// </summary>
public static class BackOfficePolicies
{
    /// <summary>A session that has chosen a context. Everything except the two selection actions.</summary>
    public const string BackOffice = "BackOffice";

    /// <summary>A session that may still be choosing one: either scope is accepted. Exactly two
    /// actions carry it, and they are the two a pre-tenant token may reach.</summary>
    public const string TenantSelection = "BackOfficeTenantSelection";
}

/// <summary>The OAuth scopes those policies are built on.</summary>
public static class BackOfficeScopes
{
    public const string BackOffice = "backoffice";

    public const string PreTenant = "backoffice_pre_tenant";
}

/// <summary>
/// Reads the back-office caller out of validated token claims.
/// <para>
/// It lives beside the controllers rather than in the shared authentication folder only because
/// that folder belongs to another slice while this one is being written; it is an adapter, and the
/// application layer never sees a <see cref="ClaimsPrincipal"/>.
/// </para>
/// </summary>
public static class BackOfficeCallerReader
{
    /// <summary>The claim carrying the chosen context. Its absence is a caller with no context,
    /// which every guard treats as "no authority" rather than as "unrestricted".</summary>
    public const string ActClaimType = "act";

    /// <summary>The token version the credential was minted against. It keys the authority
    /// snapshot, so a stale value simply misses the cache rather than widening anything.</summary>
    public const string TokenVersionClaimType = "ver";

    private static readonly JsonSerializerOptions ActJson = new(JsonSerializerDefaults.Web);

    public static BackOfficeCaller Read(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var subject = principal.FindFirstValue(ClaimTypes.NameIdentifier)
                      ?? principal.FindFirstValue("sub");

        var userId = int.TryParse(subject, CultureInfo.InvariantCulture, out var parsed) ? parsed : 0;

        var actorName = principal.FindFirstValue(ClaimTypes.Name)
                        ?? principal.FindFirstValue("name")
                        ?? string.Empty;

        var tokenVersion = int.TryParse(
            principal.FindFirstValue(TokenVersionClaimType), CultureInfo.InvariantCulture, out var ver)
            ? ver
            : 0;

        // The session behind this credential. Read here rather than by each caller that wants it,
        // so "which session am I" is answered by the same reader that answers "which context am I
        // in" - a context switch has to retire one and mint the other in the same breath, and two
        // readers is how those two answers come from different tokens.
        var sessionId = principal.FindFirstValue(AuthenticationSchemes.SessionIdClaimType)
                        ?? string.Empty;

        return new BackOfficeCaller(userId, actorName, ReadAct(principal), tokenVersion, sessionId);
    }

    private static ActClaim? ReadAct(ClaimsPrincipal principal)
    {
        var raw = principal.FindFirstValue(ActClaimType);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        try
        {
            var act = JsonSerializer.Deserialize<ActClaimPayload>(raw, ActJson);

            return act is null || string.IsNullOrEmpty(act.Type)
                ? null
                : new ActClaim(act.Type, act.Code ?? string.Empty, act.Dim ?? string.Empty, act.IsAdmin);
        }
        catch (JsonException)
        {
            // A malformed claim is treated as no context at all. It must never be read as a wider
            // one, and throwing here would answer a shaped-token problem with a 500.
            return null;
        }
    }

    /// <summary>The wire shape of the act claim: short keys, because it travels in every token.</summary>
    private sealed record ActClaimPayload
    {
        [JsonPropertyName("type")]
        public string Type { get; init; } = string.Empty;

        [JsonPropertyName("code")]
        public string? Code { get; init; }

        [JsonPropertyName("dim")]
        public string? Dim { get; init; }

        [JsonPropertyName("is_admin")]
        public bool IsAdmin { get; init; }
    }
}

/// <summary>
/// The permission gate for back-office routes.
/// <para>
/// This is the part the Go service did with a <c>RequirePermission</c> route middleware, and it is
/// not decoration. The tenant guards inside the application service answer "may this caller reach
/// this tenant at all" and "is this caller an administrator of it"; neither of them answers "was
/// this caller granted this permission code". Without this, a plain member of a tenant could read
/// its whole roster - names, decrypted e-mail addresses and role bindings - because reading your
/// own tenant's roster deliberately does not require administrator standing. It is meant to require
/// <c>uam.member.read</c> instead, and that requirement has to exist somewhere.
/// </para>
/// <para>
/// The permission set comes from the authority snapshot rather than from the token, because the
/// token is a pure identity ticket here: permissions are recomputed per request, so one taken away
/// is gone on the next call rather than at the next sign-in. <b>It fails closed.</b> A caller with
/// no context, or a snapshot that cannot be read, is refused - unlike the shell endpoint, which
/// reports an unreadable snapshot as "not delivered". The difference is deliberate: /me describes
/// the caller to themselves, these routes act on other people.
/// </para>
/// </summary>
public static class BackOfficePermissions
{
    public static async Task RequireAsync(
        IAuthzSnapshotProvider snapshots,
        BackOfficeCaller caller,
        string permissionCode,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(snapshots);
        ArgumentNullException.ThrowIfNull(caller);

        var userId = caller.RequireUserId();
        var act = caller.Act
                  ?? throw new ForbiddenException(
                      ErrorCodes.TenantNotAuthorized, "The session has no active tenant context.");

        // An act type this build does not recognise is no context at all - the same answer a missing
        // claim gets above, and the same one BackOfficeAuthzMiddleware already gives by refusing to
        // resolve a face for it. Without this the two paths disagreed: the middleware failed closed
        // while this gate handed the value straight to the context funnel, whose "unknown type" arm
        // is a 500. Measured: a token carrying act {"type":"MARS"} answered
        // GET .../tenants/company/C001/members with 500 INTERNAL_ERROR. A claim value is data, and a
        // claim this service no longer mints - an older build's, a downgraded one's - must read as
        // "holds nothing", never as a server fault.
        if (!ActTypes.IsKnown(act.Type))
        {
            throw new ForbiddenException(
                ErrorCodes.TenantNotAuthorized, "The session has no active tenant context.");
        }

        AuthzSnapshot snapshot;
        try
        {
            snapshot = await snapshots.GetOrComputeAsync(userId, act, caller.TokenVersion, cancellationToken);
        }
        catch (AppException)
        {
            // The snapshot refused for a reason of its own - an inactive account, a context the
            // caller no longer holds. Let it answer; it is more specific than this gate is.
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new ForbiddenException(
                ErrorCodes.Forbidden,
                "Your permissions could not be established for this request.",
                ex);
        }

        if (!snapshot.Permissions.Contains(permissionCode, StringComparer.Ordinal))
        {
            throw new ForbiddenException(
                ErrorCodes.Forbidden,
                $"This action requires the '{permissionCode}' permission.");
        }
    }
}
