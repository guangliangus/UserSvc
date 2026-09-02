using UserSvc.Application.Errors;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Features.BackOffice.Tenants;

/// <summary>
/// Who is calling, and in which context.
/// <para>
/// Passed in from the API layer rather than resolved through <c>ICurrentUser</c>, because a
/// back-office caller carries one thing a consumer caller does not: the <see cref="Act"/> claim
/// that says which tenant this session is currently acting in. Every guard in this slice is a
/// function of that claim plus the database, and passing it explicitly is what makes those guards
/// testable without a request.
/// </para>
/// </summary>
/// <param name="UserId">The token subject.</param>
/// <param name="ActorName">Display name, recorded in the audit trail so a row stays readable after
/// the account is renamed or removed.</param>
/// <param name="Act">Null for a token that has not chosen a context yet, and for one that carries
/// no authority at all. Null is never treated as "unrestricted".</param>
/// <param name="TokenVersion">The account's token version at the moment this token was minted. It
/// is the cache key of the authority snapshot, which is how a permission taken away lands on the
/// next request instead of at the next sign-in.</param>
public sealed record BackOfficeCaller(
    int UserId, string ActorName, ActClaim? Act, int TokenVersion = 0)
{
    /// <summary>
    /// The tenant this caller is acting in, or null when it is acting globally. The
    /// whole-dimension sentinel deliberately resolves to null: a global standing is not a tenant.
    /// </summary>
    public (string TenantType, string TenantCode)? TenantRef()
    {
        if (Act is null || Act.Type is not (ActTypes.Company or ActTypes.Supplier))
        {
            return null;
        }

        return string.IsNullOrEmpty(Act.Code) || Act.Code == TenantScopes.ScopeAllSentinelCode
            ? null
            : (ActTypes.ToTenantType(Act.Type), Act.Code);
    }

    /// <summary>Rejects a caller the API layer could not identify. It is a 401 rather than a 403:
    /// there is nothing to authorize yet.</summary>
    public int RequireUserId() => UserId > 0
        ? UserId
        : throw new UnauthorizedException(ErrorCodes.Unauthorized, "The token carries no usable user id.");
}
