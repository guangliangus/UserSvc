using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace BuildingBlocks.Web.Auth;

/// <summary>
/// Scope-based authorization helpers. OAuth2 puts every granted scope into ONE space-separated
/// "scope" claim (MapInboundClaims=false keeps the raw name), so RequireClaim can't match it —
/// the value has to be split.
/// </summary>
public static class AuthorizationPolicyExtensions
{
    /// <summary>
    /// Named policy that passes when the token's scope claim contains <paramref name="requiredScope"/>.
    /// Audience validation already restricts tokens to THIS api; scopes add per-operation
    /// granularity (read vs write), so a read-only client can never mutate state.
    /// </summary>
    public static AuthorizationOptions AddScopePolicy(this AuthorizationOptions options, string name, string requiredScope)
    {
        options.AddPolicy(name, policy => policy
            .RequireAuthenticatedUser()
            .RequireAssertion(context => HasScope(context.User, requiredScope)));
        return options;
    }

    public static bool HasScope(ClaimsPrincipal user, string requiredScope)
    {
        foreach (var claim in user.FindAll("scope"))
        {
            foreach (var scope in claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (string.Equals(scope, requiredScope, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
