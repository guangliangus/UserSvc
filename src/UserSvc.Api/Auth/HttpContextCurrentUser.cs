using System.Globalization;
using System.Security.Claims;
using UserSvc.Api.Controllers.BackOffice;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Auth;

namespace UserSvc.Api.Auth;

/// <summary>Reads the caller from validated token claims. The adapter lives in the API layer;
/// the application layer only ever sees <see cref="ICurrentUser"/>.</summary>
public sealed class HttpContextCurrentUser(IHttpContextAccessor accessor) : ICurrentUser
{
    /// <inheritdoc />
    public int? UserId
    {
        get
        {
            var raw = accessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier)
                      ?? accessor.HttpContext?.User.FindFirstValue("sub");

            return int.TryParse(raw, CultureInfo.InvariantCulture, out var id) ? id : null;
        }
    }

    /// <inheritdoc />
    public string? SessionId =>
        accessor.HttpContext?.User.FindFirstValue(AuthenticationSchemes.SessionIdClaimType);

    /// <summary>
    /// <inheritdoc cref="ICurrentUser.Realm" path="/summary/para[1]" />
    /// <para>
    /// Either back-office scope makes the caller a back-office subject, which is the same reading
    /// <c>AuthValidationController.ReadTokenFacts</c> takes: a pre-tenant token is still a
    /// back-office one, it has just not chosen where it is acting yet. Anything else is a consumer
    /// token, and that is the one direction in which a default is safe here - a consumer subject
    /// can reach only the consumer's own rows, so mislabelling a back-office token as a consumer
    /// would have to get past the back-office policies first, which are built on the same claim.
    /// </para>
    /// </summary>
    public string Realm =>
        HasBackOfficeScope() ? SessionRealms.BackOffice : SessionRealms.Consumer;

    /// <inheritdoc />
    public int RequireUserId() =>
        UserId ?? throw new UnauthorizedException(ErrorCodes.Unauthorized, "Authentication is required.");

    /// <summary>
    /// Reads the scope claim in both of its legal shapes - one claim per scope, or a single
    /// space-delimited string - for the same reason the authorization policies do: OpenIddict emits
    /// the first, and a token minted by an older build can present the second.
    /// </summary>
    private bool HasBackOfficeScope()
    {
        var principal = accessor.HttpContext?.User;
        if (principal is null)
        {
            return false;
        }

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
}
