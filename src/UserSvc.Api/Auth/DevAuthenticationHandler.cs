using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace UserSvc.Api.Auth;

/// <summary>
/// <b>Convenience for local development and the integration tests only.</b> Real tokens are issued
/// and validated in this same process by OpenIddict (decision 10); this handler exists so a curl
/// call or a test does not have to run the token endpoint first.
/// <para>
/// It fabricates an identity from the <c>X-Dev-User-Id</c> and <c>X-Dev-Session-Id</c> headers and
/// <b>validates nothing</b>. <c>OpenIddictRegistration.ConfigureSchemes</c> registers it under
/// Development only, behind a policy scheme that hands any request carrying an
/// <c>Authorization</c> header to the real validation scheme instead — so the two coexist and a
/// genuine token is never checked by this. Outside Development the scheme does not exist at all
/// and there is nothing to fall back to.
/// </para>
/// <para>
/// Returning <see cref="AuthenticateResult.NoResult"/> when the header is absent is the load-bearing
/// half: a placeholder for a security component must fail towards refusing.
/// </para>
/// </summary>
public sealed class DevAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
{
    public const string SchemeName = AuthenticationSchemes.DevHeader;

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-Dev-User-Id", out var userId) || string.IsNullOrWhiteSpace(userId))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var sessionId = Request.Headers.TryGetValue("X-Dev-Session-Id", out var sid) && !string.IsNullOrWhiteSpace(sid)
            ? sid.ToString()
            : "dev-session";

        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                new Claim(AuthenticationSchemes.SessionIdClaimType, sessionId),
            ],
            SchemeName);

        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }

    /// <summary>RFC 6750 requires a challenge to say which scheme it wants. The status-code-pages
    /// middleware supplies the ProblemDetails body; this only supplies the header.</summary>
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate = "Bearer";
        return base.HandleChallengeAsync(properties);
    }
}
