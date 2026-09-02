using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using UserSvc.Api.Controllers.BackOffice;

namespace UserSvc.Api.Auth;

/// <summary>
/// The two back-office authorization policies, built on OAuth scopes.
/// <para>
/// <b>They are built on a scope the token must carry, not on the absence of one.</b> A pre-tenant
/// session - somebody who has authenticated but not yet chosen which company or supplier they are
/// acting as - needs to reach exactly two endpoints: the list of contexts it may enter, and the one
/// that enters one. The obvious implementation is "allow the request when there is no <c>act</c>
/// claim", and it fails open: absence is also what a downgraded, malformed or foreign token looks
/// like. So a pre-tenant token is granted <see cref="BackOfficeScopes.PreTenant"/> at the token
/// endpoint and nothing else, and the two selection actions are the only ones that accept it.
/// </para>
/// <para>
/// The consumer-facing guard falls out of the same mechanism for free: a C-end token carries
/// neither scope, so both policies refuse it with a 403 rather than letting it wander into the back
/// office.
/// </para>
/// <para>
/// The scope claim is read in both of its legal shapes. OpenIddict's validation handler normally
/// splits the granted scopes into one claim each, but a token minted elsewhere - or by an older
/// build - can present them as a single space-delimited string, and a policy that understood only
/// one shape would refuse a perfectly good credential.
/// </para>
/// </summary>
public static class BackOfficeAuthorization
{
    /// <summary>The claim type OAuth 2.0 defines for granted scopes.</summary>
    public const string ScopeClaimType = "scope";

    public static AuthorizationOptions AddBackOfficePolicies(this AuthorizationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.AddPolicy(
            BackOfficePolicies.BackOffice,
            policy => policy
                .RequireAuthenticatedUser()
                .RequireAssertion(context => HasAnyScope(context.User, BackOfficeScopes.BackOffice)));

        // Either scope opens these two. A session that has already chosen a context keeps working -
        // the context chooser stays reachable for a switch - and one that has not is let in for
        // exactly this and nothing more.
        options.AddPolicy(
            BackOfficePolicies.TenantSelection,
            policy => policy
                .RequireAuthenticatedUser()
                .RequireAssertion(context => HasAnyScope(
                    context.User, BackOfficeScopes.BackOffice, BackOfficeScopes.PreTenant)));

        return options;
    }

    private static bool HasAnyScope(ClaimsPrincipal principal, params string[] wanted)
    {
        foreach (var claim in principal.FindAll(ScopeClaimType))
        {
            foreach (var granted in claim.Value.Split(
                         ' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (Array.IndexOf(wanted, granted) >= 0)
                {
                    return true;
                }
            }
        }

        return false;
    }
}
