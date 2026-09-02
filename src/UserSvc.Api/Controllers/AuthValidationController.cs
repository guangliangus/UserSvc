using System.Globalization;
using System.Security.Claims;
using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Api.Auth;
using UserSvc.Api.Controllers.BackOffice;
using UserSvc.Application.Features.Auth.TokenValidation;

namespace UserSvc.Api.Controllers;

/// <summary>
/// Token introspection for the services that sit behind this one.
/// <para>
/// <b>Half of the endpoint this ports is now redundant, and half of it is not.</b> The Go original
/// signed access tokens with a shared HMAC secret, so a relying service could not check a signature
/// without holding the secret; <c>POST /auth/validate</c> therefore did four jobs at once —
/// signature and expiry, revocation, authority projection, and the test-user flag. This service
/// issues real asymmetrically signed tokens and publishes its keys, so <b>signature, issuer,
/// audience and expiry are now checked locally by every caller</b> and porting that half would be a
/// second implementation of a check that already has one, on the platform's hottest path.
/// </para>
/// <para>
/// What JWKS cannot answer is what is left, and it is the reason this endpoint still exists:
/// </para>
/// <list type="number">
/// <item><description>
/// <b>Is the session still alive?</b> Signing a device out revokes the token chain and marks the
/// session row, but the access token already in that device's hands stays cryptographically
/// perfect until it expires. A relying service validating locally cannot see that, and this is the
/// only place that can tell it.
/// </description></item>
/// <item><description>
/// <b>What does the holder currently hold?</b> The access token here is an <i>identity ticket</i>:
/// look at the token endpoint and you will find exactly two claims destined for it, <c>sub</c> and
/// <c>sid</c>. Roles, permissions, menus and data scopes are recomputed from the database on every
/// request precisely so that a permission taken away stops working on the next call rather than at
/// the next sign-in. A relying service has nowhere else to read them from.
/// </description></item>
/// <item><description>
/// <b>Is this consumer a test user?</b> A verdict that lives in this service's own store and in no
/// token, read per call so that whitelisting somebody lands on their next request. It is asked for
/// consumer tokens only - see <see cref="TokenValidationResponse.IsTest"/>.
/// </description></item>
/// </list>
/// <para>
/// <b>The token travels in the <c>Authorization</c> header, not in the body</b> - the one shape
/// change from the Go contract, and it is deliberate. With the validation half gone there is no
/// reason to accept a token anywhere but the standard place; the relying services already hold the
/// end user's bearer token and forward headers routinely. It also closes something the body form
/// left open: a body-token endpoint has to be anonymous, which makes it an oracle anyone on the
/// network can feed candidate tokens to. Here the authentication stack refuses an invalid token
/// before this controller is reached. Relying callers move one string; nobody gets an oracle.
/// </para>
/// <para>
/// <b>There is no soft-error envelope.</b> Go answered every outcome with HTTP 200 and a verdict in
/// the body. This service answers RFC 9457 with real status codes, so an invalid token is a 401
/// whose <c>errorCode</c> carries the same branch the Go client read: <c>EXPIRED_TOKEN</c> means
/// refresh, <c>INVALID_TOKEN</c> and <c>SESSION_REVOKED</c> mean sign in again,
/// <c>TENANT_CONTEXT_REQUIRED</c> means choose a company first, and a 5xx means retry without
/// signing anybody out.
/// </para>
/// </summary>
[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/auth")]
[Produces("application/json")]
public sealed class AuthValidationController(TokenValidationAppService tokens) : ControllerBase
{
    /// <summary>The claim carrying the token's expiry, in Unix seconds.</summary>
    private const string ExpiresAtClaimType = "exp";

    /// <summary>The claim carrying the token's issue time, in Unix seconds.</summary>
    private const string IssuedAtClaimType = "iat";

    /// <summary>
    /// Describe the presented access token: whether its session is still live, and what its holder
    /// currently holds.
    /// </summary>
    /// <response code="200">The token is live. The body carries the caller's current authority.</response>
    /// <response code="401">No token, a token that failed validation, a signed-out session, or a
    /// back-office session that has not chosen a context yet. The <c>errorCode</c> says which.</response>
    /// <response code="500">The session row could not be read. Retry; do not sign the user out.</response>
    [HttpPost("validate")]
    [Authorize]
    [ProducesResponseType<TokenValidationResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public Task<TokenValidationResponse> Validate(CancellationToken cancellationToken) =>
        tokens.DescribeAsync(ReadTokenFacts(User), cancellationToken);

    /// <summary>
    /// The facts that can only be read from the principal. Everything else the response carries is
    /// resolved by the request pipeline or read from the session row.
    /// </summary>
    private static ValidatedTokenFacts ReadTokenFacts(ClaimsPrincipal principal)
    {
        var backOffice = HasAnyScope(principal, BackOfficeScopes.BackOffice);
        var preTenant = HasAnyScope(principal, BackOfficeScopes.PreTenant);

        return new ValidatedTokenFacts
        {
            SessionId = principal.FindFirstValue(AuthenticationSchemes.SessionIdClaimType) ?? string.Empty,

            // Either back-office scope makes this an internal credential. A pre-tenant token is
            // still a back-office one - it just has not chosen where it is acting yet - and calling
            // it a consumer token would report a consumer-shaped answer for a back-office account.
            IsInternal = backOffice || preTenant,

            // A token holding only the pre-tenant scope. One that holds the full scope as well has
            // already made its choice: the chooser stays reachable for a later switch, so both
            // scopes together is a normal, contextful session.
            AwaitingTenantContext = preTenant && !backOffice,

            IsTenantAdmin = BackOfficeCallerReader.Read(principal).Act?.IsAdmin ?? false,
            IssuedAt = UnixSecondsClaim(principal, IssuedAtClaimType),
            ExpiresAt = UnixSecondsClaim(principal, ExpiresAtClaimType),
        };
    }

    /// <summary>
    /// Reads the scope claim in both of its legal shapes - one claim per scope, or a single
    /// space-delimited string - for the same reason the authorization policies do: OpenIddict emits
    /// the first, and a token minted by an older build can present the second. A reader that
    /// understood only one shape would report a perfectly good back-office token as a consumer's.
    /// </summary>
    private static bool HasAnyScope(ClaimsPrincipal principal, string wanted)
    {
        foreach (var claim in principal.FindAll(BackOfficeAuthorization.ScopeClaimType))
        {
            foreach (var granted in claim.Value.Split(
                         ' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (string.Equals(granted, wanted, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// A Unix-seconds claim, or null when the principal has none.
    /// <para>
    /// Null is a real outcome rather than an error: the development authentication handler
    /// fabricates identities from headers and mints no lifetime at all, so a local caller sees
    /// <c>expiresIn: 0</c> and no timestamps. Refusing such a principal would break the local curl
    /// and integration-test workflow the handler exists to serve, and it says nothing about whether
    /// the session is alive - which is the question this endpoint actually answers.
    /// </para>
    /// </summary>
    private static DateTimeOffset? UnixSecondsClaim(ClaimsPrincipal principal, string claimType) =>
        long.TryParse(
            principal.FindFirstValue(claimType), CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
}
