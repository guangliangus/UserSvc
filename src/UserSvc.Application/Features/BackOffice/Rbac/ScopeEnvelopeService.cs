using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac.Contracts;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>
/// The data-scope envelope: which company and supplier codes an account's data reads are bounded to.
/// <para>
/// Breadth, never authority. Nothing in this file decides what someone may <i>do</i>; it decides
/// which rows they may see when they do it.
/// </para>
/// </summary>
public sealed class ScopeEnvelopeService(
    AdminScopeService adminScopes,
    ITenantMemberDirectory members)
{
    /// <summary>
    /// The envelope of one account.
    /// <para>
    /// The platform super administrator short-circuits to global in both dimensions: their breadth is
    /// hard-coded by the identity, not carried by membership rows, so summing rows would report an
    /// empty envelope for the widest account in the system.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyDictionary<string, ScopeClaim>> LoadUserScopeClaimsAsync(
        int userId,
        CancellationToken cancellationToken)
    {
        if (await adminScopes.IsPlatformSuperAdminAsync(userId, cancellationToken))
        {
            return AllGlobal();
        }

        var memberships = await members.ListActiveByUserAsync(userId, cancellationToken);
        return Aggregate(userId, memberships);
    }

    /// <summary>Both dimensions global.</summary>
    public static IReadOnlyDictionary<string, ScopeClaim> AllGlobal() =>
        new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
        {
            [TenantTypes.Company] = ScopeClaim.Global,
            [TenantTypes.Supplier] = ScopeClaim.Global,
        };

    /// <summary>
    /// Both dimensions present and empty.
    /// <para>
    /// Declared explicitly rather than left out, so a consumer reads "granted nothing" instead of
    /// "this key is missing, maybe it means everything".
    /// </para>
    /// </summary>
    public static IReadOnlyDictionary<string, ScopeClaim> Empty() =>
        new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
        {
            [TenantTypes.Company] = ScopeClaim.Empty,
            [TenantTypes.Supplier] = ScopeClaim.Empty,
        };

    /// <summary>
    /// Fold membership rows into one envelope per dimension.
    /// </summary>
    public static IReadOnlyDictionary<string, ScopeClaim> Aggregate(
        int userId,
        IReadOnlyList<TenantMembershipRow> memberships)
    {
        var result = new Dictionary<string, ScopeClaim>(StringComparer.Ordinal);
        if (memberships.Count == 0)
        {
            return result;
        }

        var valuesByType = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var globalTypes = new HashSet<string>(StringComparer.Ordinal);

        foreach (var membership in memberships)
        {
            if (!TenantTypes.IsAllowed(membership.TenantType))
            {
                // Loud rather than silent: an unknown dimension here means a row nobody can reason
                // about, and quietly dropping it would understate somebody's breadth.
                throw new BadRequestException(
                    ErrorCodes.BadRequest,
                    $"Invalid tenant type for user {userId}: {membership.TenantType}.");
            }

            if (membership.ScopeAll)
            {
                // The sentinel code is never treated as a value, and a whole-dimension row overrides
                // every specific row on the same side.
                globalTypes.Add(membership.TenantType);
                continue;
            }

            if (!valuesByType.TryGetValue(membership.TenantType, out var values))
            {
                values = [];
                valuesByType[membership.TenantType] = values;
            }

            values.Add(membership.TenantCode);
        }

        // Fixed dimension order, so the same set of rows always produces the same bytes.
        foreach (var tenantType in TenantTypes.All)
        {
            if (globalTypes.Contains(tenantType))
            {
                result[tenantType] = ScopeClaim.Global;
                continue;
            }

            if (valuesByType.TryGetValue(tenantType, out var values))
            {
                result[tenantType] = new ScopeClaim(Canonicalize(values), false);
            }
        }

        return result;
    }

    /// <summary>Trimmed, blank-free, deduplicated and sorted. Never null - an empty list is the
    /// answer, and it means "no codes", which is different from "every code".</summary>
    public static IReadOnlyList<string> Canonicalize(IEnumerable<string> values) =>
    [
        .. values
            .Select(value => value.Trim())
            .Where(value => value.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal),
    ];

    /// <summary>The envelope in wire shape, in the fixed dimension order.</summary>
    public static IReadOnlyList<RoleScopeResponse> BuildUserScopes(
        IReadOnlyDictionary<string, ScopeClaim> claims)
    {
        if (claims.Count == 0)
        {
            return [];
        }

        var result = new List<RoleScopeResponse>(claims.Count);
        foreach (var tenantType in TenantTypes.All)
        {
            if (!claims.TryGetValue(tenantType, out var claim))
            {
                continue;
            }

            result.Add(new RoleScopeResponse
            {
                ScopeType = tenantType,
                Values = claim.IsGlobal ? [] : Canonicalize(claim.Values),
                IsGlobal = claim.IsGlobal,
            });
        }

        return result;
    }
}
