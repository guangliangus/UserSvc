using System.Globalization;
using System.Security.Claims;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Api.Auth;

/// <summary>Reads the caller from validated token claims. The adapter lives in the API layer;
/// the application layer only ever sees <see cref="ICurrentUser"/>.</summary>
public sealed class HttpContextCurrentUser(IHttpContextAccessor accessor) : ICurrentUser
{
    public int? UserId
    {
        get
        {
            var raw = accessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier)
                      ?? accessor.HttpContext?.User.FindFirstValue("sub");

            return int.TryParse(raw, CultureInfo.InvariantCulture, out var id) ? id : null;
        }
    }

    public string? SessionId =>
        accessor.HttpContext?.User.FindFirstValue(AuthenticationSchemes.SessionIdClaimType);

    public int RequireUserId() =>
        UserId ?? throw new UnauthorizedException(ErrorCodes.Unauthorized, "Authentication is required.");
}
