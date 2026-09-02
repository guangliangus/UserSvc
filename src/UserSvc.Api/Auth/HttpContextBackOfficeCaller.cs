using System.Globalization;
using System.Security.Claims;
using UserSvc.Api.Controllers.BackOffice;
using UserSvc.Application.Ports.Iam;

namespace UserSvc.Api.Auth;

/// <summary>
/// The back-office caller, read from the validated token plus whatever authority the request
/// pipeline has already resolved. The adapter lives in the API layer; the application layer sees
/// neither HTTP nor JWT - the same arrangement as <see cref="HttpContextCurrentUser"/>, which this
/// follows deliberately.
/// <para>
/// <b>Identity comes from the token; authority never does.</b> The access token here is an identity
/// ticket - it carries no roles, permissions, scopes or menus - so the only thing read out of it
/// below is who is calling and which context they chose. What they may do is recomputed per request
/// by <see cref="BackOfficeAuthzMiddleware"/> and left in <see cref="HttpContext.Items"/>; this type
/// reads that result and, when it is absent, answers
/// <see cref="EffectiveAuthz.Empty"/>.
/// </para>
/// <para>
/// It deliberately does <b>not</b> compute the face itself. Every gate in the role slice is written
/// against this interface, and a property getter that reached for a database and a Redis round trip
/// would let any of them silently acquire authority outside the request pipeline - including on
/// paths where the pipeline decided not to grant it. Failing closed here is the point.
/// </para>
/// </summary>
public sealed class HttpContextBackOfficeCaller(IHttpContextAccessor accessor) : IBackOfficeCaller
{
    /// <summary>Where <see cref="BackOfficeAuthzMiddleware"/> leaves the resolved face.</summary>
    public const string AuthzItemKey = "usersvc.backoffice.authz";

    /// <summary>The header a gateway uses to correlate a request across services; falls back to the
    /// framework's own identifier so an audit row always has something to join on.</summary>
    private const string RequestIdHeader = "X-Request-Id";

    public int UserId
    {
        get
        {
            var raw = Principal?.FindFirstValue(ClaimTypes.NameIdentifier)
                      ?? Principal?.FindFirstValue("sub");

            // Zero, not null: "no caller" is a real answer everywhere in the role slice, and a
            // narrowing read that treats it as "the platform" is how an endpoint becomes a
            // platform-wide directory.
            return int.TryParse(raw, CultureInfo.InvariantCulture, out var id) ? id : 0;
        }
    }

    public string Nickname =>
        Principal?.FindFirstValue(ClaimTypes.Name)
        ?? Principal?.FindFirstValue("name")
        ?? string.Empty;

    public string ActType => Act?.Type ?? string.Empty;

    public string ActCode => Act?.Code ?? string.Empty;

    public string ActDim => Act?.Dimension ?? string.Empty;

    public string? IpAddress => accessor.HttpContext?.Connection.RemoteIpAddress?.ToString();

    public string? RequestId
    {
        get
        {
            var context = accessor.HttpContext;
            if (context is null)
            {
                return null;
            }

            return context.Request.Headers.TryGetValue(RequestIdHeader, out var header)
                   && !string.IsNullOrWhiteSpace(header)
                ? header.ToString()
                : context.TraceIdentifier;
        }
    }

    public EffectiveAuthz Authz =>
        accessor.HttpContext?.Items.TryGetValue(AuthzItemKey, out var stored) == true
        && stored is EffectiveAuthz face
            ? face
            : EffectiveAuthz.Empty;

    private ClaimsPrincipal? Principal => accessor.HttpContext?.User;

    /// <summary>
    /// Parsed by the same reader the tenancy controllers use, so a malformed or absent
    /// <c>act</c> claim means one thing across the whole back office: no context, never a wider one.
    /// </summary>
    private Domain.Tenancy.ActClaim? Act =>
        Principal is null ? null : BackOfficeCallerReader.Read(Principal).Act;
}
