using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace UserSvc.Api.Auth;

/// <summary>
/// <b>Placeholder — local development and integration tests only.</b> The real thing is OpenIddict
/// issuing tokens and JwtBearer validating them (decision 10).
/// <para>
/// It fabricates an identity from the <c>X-Dev-User-Id</c> and <c>X-Dev-Session-Id</c> headers and
/// <b>validates nothing</b>. It is registered under Development only (see <c>Program.cs</c>);
/// outside it the app fails to start for want of an authentication scheme rather than quietly
/// letting requests through — a placeholder for a security component must pick the refusing side.
/// </para>
/// </summary>
public sealed class DevAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
{
    public const string SchemeName = "DevHeader";

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
            [new Claim(ClaimTypes.NameIdentifier, userId.ToString()), new Claim("sid", sessionId)],
            SchemeName);

        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}
