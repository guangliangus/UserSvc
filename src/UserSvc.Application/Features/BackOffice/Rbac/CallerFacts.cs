using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>
/// Plain readings of the caller's acting context. No I/O, no policy - every one of these is a
/// question about the token that several guards ask, and they are gathered here so the answers
/// cannot drift apart.
/// </summary>
public static class CallerFacts
{
    /// <summary>
    /// The tenant the caller is acting as, if any.
    /// <para>
    /// PLATFORM, GLOBAL and an absent context all answer "not a tenant" - which is what exempts them
    /// from the subset-of-creator delegation rule. A whole-dimension operator is not a tenant.
    /// </para>
    /// </summary>
    public static (string TenantType, string TenantCode, bool IsTenant) Tenant(IBackOfficeCaller caller) =>
        caller.ActType switch
        {
            ActTypes.Company => (TenantTypes.Company, caller.ActCode, true),
            ActTypes.Supplier => (TenantTypes.Supplier, caller.ActCode, true),
            _ => (string.Empty, string.Empty, false),
        };

    /// <summary>
    /// The acting tenant as a reference pair, or two empty strings.
    /// <para>
    /// Differs from <see cref="Tenant"/> in one way that matters: a blank code, or the <c>*</c>
    /// sentinel, resolves to nothing. <c>*</c> is not a tenant.
    /// </para>
    /// </summary>
    public static (string TenantType, string TenantCode) ActTenantRef(IBackOfficeCaller caller)
    {
        var (tenantType, tenantCode, isTenant) = Tenant(caller);
        if (!isTenant)
        {
            return (string.Empty, string.Empty);
        }

        var trimmed = tenantCode.Trim();
        return trimmed.Length == 0 || trimmed == IamConstants.ScopeAllSentinelCode
            ? (string.Empty, string.Empty)
            : (tenantType, trimmed);
    }

    /// <summary>The dimension this session is locked to: its tenant's dimension, or a GLOBAL
    /// session's chosen one. Empty for the platform, and for a GLOBAL token minted before dimension
    /// selection existed - which meant both dimensions.</summary>
    public static string ActDimension(IBackOfficeCaller caller) => caller.ActType switch
    {
        ActTypes.Company => TenantTypes.Company,
        ActTypes.Supplier => TenantTypes.Supplier,
        ActTypes.Global => GlobalActDimension(caller),
        _ => string.Empty,
    };

    /// <summary>
    /// The dimension of a GLOBAL session only. Empty for everything else, including a tenant
    /// session.
    /// <para>
    /// Used where membership is already the narrower axis and an extra tenant narrowing would be
    /// wrong - the peer directory being the case in point. The difference from
    /// <see cref="ActDimension"/> is deliberate; unifying them breaks one of the two.
    /// </para>
    /// </summary>
    public static string GlobalActDimension(IBackOfficeCaller caller) =>
        caller.ActType == ActTypes.Global && TenantTypes.IsAllowed(caller.ActDim)
            ? caller.ActDim
            : string.Empty;

    /// <summary>Whether this scope claim names the tenant that owns a role.
    /// <para>
    /// A global claim deliberately does <b>not</b> count. Breadth over data is not authority over
    /// another tenant's role definitions: reading it as such made every company's private roles
    /// legible to anyone holding "all companies".
    /// </para>
    /// </summary>
    public static bool ScopeCoversOwnerCode(ScopeClaim claim, string? ownerCode) =>
        !string.IsNullOrEmpty(ownerCode) && claim.Values.Contains(ownerCode);

    /// <summary>Sorted, deduplicated ids - so a query built from a set is stable and its expected
    /// arguments are matchable in a test.</summary>
    public static IReadOnlyList<int> DedupeSort(IEnumerable<int> ids) =>
        [.. ids.Distinct().Order()];

    /// <summary>Deduplicated, order preserving, blanks dropped.</summary>
    public static IReadOnlyList<string> DedupeStrings(IEnumerable<string>? values)
    {
        if (values is null)
        {
            return [];
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        return [.. values.Where(value => !string.IsNullOrEmpty(value) && seen.Add(value))];
    }

    /// <summary>Whether every element of <paramref name="subset"/> is present in
    /// <paramref name="superset"/>.</summary>
    public static bool IsSubsetOf(IEnumerable<string> subset, IEnumerable<string> superset)
    {
        var lookup = superset.ToHashSet(StringComparer.Ordinal);
        return subset.All(lookup.Contains);
    }
}
