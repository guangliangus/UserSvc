using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>
/// The delegation ceiling: which roles one caller may hand to somebody else inside a given tenant.
/// <para>
/// Category rules sit <i>beside</i> this, not inside it. A role of the wrong category is refused with
/// its own code by <see cref="AssertRolesFitTenantTypeAsync"/>; folding that into the ceiling would
/// collapse both answers into "beyond your delegable range", which is the wrong thing to tell a
/// caller whose authority was never in question.
/// </para>
/// </summary>
public sealed class RoleDelegationService(
    AdminScopeService adminScopes,
    ITenantMemberDirectory members,
    IUserTenantRoleRepository bindings,
    IRoleRepository roles)
{
    /// <summary>The role ids this caller may bind inside this tenant.</summary>
    public async Task<IReadOnlyList<int>> DelegableRoleIdsAsync(
        int callerUserId,
        string tenantType,
        string tenantCode,
        CancellationToken cancellationToken)
    {
        return await adminScopes.IsPlatformSuperAdminAsync(callerUserId, cancellationToken)
            ? await AllBindableRoleIdsAsync(tenantType, tenantCode, cancellationToken)
            : await TenantDelegableRoleIdsAsync(callerUserId, tenantType, tenantCode, cancellationToken);
    }

    /// <summary>
    /// The union of the ceilings the caller's specific membership and their whole-dimension membership
    /// give them, because member management accepts either standing.
    /// <para>
    /// It is needed because the ceiling is derived from whichever membership row the lookup was given:
    /// a non-super-administrator who manages a whole dimension has no row in the target tenant, so
    /// asking about that tenant alone resolves to an <b>empty</b> ceiling - they could add members
    /// anywhere on their side and every non-empty role list came back refused. Fail-closed, but the
    /// workflow was simply broken.
    /// </para>
    /// <para>
    /// It widens nothing for anybody else: a tenant administrator has no <c>*</c> row, so that query
    /// returns nothing, and the super-administrator branch already answered everything on its first
    /// call. One thing it deliberately cannot reach: the target tenant's <b>own</b> custom roles when
    /// the caller's standing comes from the <c>*</c> row, because <c>*</c> owns nothing. Granting too
    /// little is the safe direction.
    /// </para>
    /// </summary>
    public async Task<HashSet<int>> DelegableRoleSetAsync(
        int callerUserId,
        string tenantType,
        string tenantCode,
        CancellationToken cancellationToken)
    {
        var union = new HashSet<int>();
        foreach (var code in new[] { tenantCode, IamConstants.ScopeAllSentinelCode })
        {
            foreach (var id in await DelegableRoleIdsAsync(callerUserId, tenantType, code, cancellationToken))
            {
                union.Add(id);
            }
        }

        return union;
    }

    /// <summary>The codes among <paramref name="roleIds"/> that are outside the caller's ceiling.</summary>
    public async Task<IReadOnlyList<string>> ValidateDelegationAsync(
        int callerUserId,
        string tenantType,
        string tenantCode,
        IReadOnlyCollection<int> roleIds,
        CancellationToken cancellationToken)
    {
        if (roleIds.Count == 0)
        {
            return [];
        }

        var delegable = (await DelegableRoleIdsAsync(callerUserId, tenantType, tenantCode, cancellationToken))
            .ToHashSet();

        var violating = roleIds.Where(id => !delegable.Contains(id)).ToList();
        if (violating.Count == 0)
        {
            return [];
        }

        var offending = await roles.FindByIdsAsync(CallerFacts.DedupeSort(violating), cancellationToken);
        return [.. offending.Select(role => role.Code).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    }

    /// <summary>Every role in <paramref name="roleIds"/> must be categorised for this kind of tenant.</summary>
    public async Task AssertRolesFitTenantTypeAsync(
        string tenantType,
        IReadOnlyCollection<int> roleIds,
        CancellationToken cancellationToken)
    {
        var ids = CallerFacts.DedupeSort(roleIds);
        if (ids.Count == 0)
        {
            return;
        }

        var found = await roles.FindByIdsAsync(ids, cancellationToken);
        var violations = found
            .Where(role => !RoleCategories.BindableTo(role.Category, tenantType))
            .Select(role => role.Code)
            .Order(StringComparer.Ordinal)
            .ToList();

        if (violations.Count > 0)
        {
            throw new RoleSetException(
                ErrorCodes.RoleCategoryMismatch,
                "One or more roles are not categorised for this kind of tenant.",
                violations);
        }
    }

    /// <summary>
    /// Refuse a tenant's own role on a whole-dimension grant.
    /// <para>
    /// A whole-dimension membership is <b>one</b> row whose role set takes effect inside every tenant
    /// on that side. A role a company wrote for itself only means something in that company; bound to
    /// "all companies" it takes effect in every other company too, going around the ownership boundary
    /// that the per-tenant path draws naturally. That path derives the boundary from the delegation
    /// ceiling; a whole-dimension grant resolves no ceiling at all - only the platform owner can reach
    /// it, and their ceiling is everything - so it has to be said out loud here.
    /// </para>
    /// </summary>
    public static void AssertNoTenantOwnedRoles(IReadOnlyList<Role> candidates)
    {
        var violations = candidates
            .Where(role => role.IsTenantOwned())
            .Select(role => role.Code)
            .Order(StringComparer.Ordinal)
            .ToList();

        if (violations.Count > 0)
        {
            throw new RoleSetException(
                ErrorCodes.RoleNotGloballyAssignable,
                "A tenant's own role cannot be granted on a whole-dimension scope; use a built-in role.",
                violations);
        }
    }

    /// <summary>Everything the platform super administrator may bind inside one tenant: every
    /// built-in role, group leaders included, plus that tenant's own roles. Roles belonging to
    /// <i>other</i> tenants stay out - administering tenant X must never offer tenant Y's private
    /// roles.</summary>
    private async Task<IReadOnlyList<int>> AllBindableRoleIdsAsync(
        string tenantType,
        string tenantCode,
        CancellationToken cancellationToken)
    {
        var all = await roles.ListAllAsync(cancellationToken);
        return CallerFacts.DedupeSort(all
            .Where(role => !role.IsOtherTenantRole(tenantType, tenantCode))
            .Select(role => role.Id));
    }

    /// <summary>
    /// A tenant caller's ceiling: everything strictly <b>below</b> the administrator roles they hold
    /// in that tenant.
    /// <para>
    /// Three things are deliberately absent. Their own administrator roles - "below me" excludes me,
    /// so an administrator cannot clone themselves onto a peer; appointing another one is their
    /// leader's job. Their non-administrator roles - holding a role is not authority to hand it out;
    /// only leaders delegate. And every role belonging to another tenant, even one filed under a
    /// shared platform leader. Administrator roles <i>under</i> their leader are delegable: that is
    /// how a three-level tree appoints its sub-leaders.
    /// </para>
    /// </summary>
    private async Task<IReadOnlyList<int>> TenantDelegableRoleIdsAsync(
        int callerUserId,
        string tenantType,
        string tenantCode,
        CancellationToken cancellationToken)
    {
        var membership = await members.FindAsync(callerUserId, tenantType, tenantCode, cancellationToken);
        if (membership is null || membership.Status != TenantMembershipStatuses.Active)
        {
            return [];
        }

        var bound = await bindings.ListByMemberIdAsync(membership.Id, cancellationToken);
        var boundIds = CallerFacts.DedupeSort(bound.Select(binding => binding.RoleId));
        if (boundIds.Count == 0)
        {
            return [];
        }

        var boundRoles = await roles.FindByIdsAsync(boundIds, cancellationToken);
        var adminRoleIds = CallerFacts.DedupeSort(
            boundRoles.Where(role => role.IsAdmin).Select(role => role.Id));

        if (adminRoleIds.Count == 0)
        {
            return [];
        }

        var descendants = await roles.ListDescendantsAsync(adminRoleIds, cancellationToken);
        return CallerFacts.DedupeSort(descendants
            .Where(role => !role.IsOtherTenantRole(tenantType, tenantCode))
            .Select(role => role.Id));
    }
}

/// <summary>
/// A refusal that names the offending role codes. They travel as a <c>roles</c> extension member on
/// the problem document, so the form can mark the exact chips rather than make the operator guess.
/// </summary>
public sealed class RoleSetException(string errorCode, string message, IReadOnlyList<string> roles)
    : AppException(errorCode, message, 400)
{
    /// <summary>The offending role codes, sorted.</summary>
    public IReadOnlyList<string> Roles { get; } = roles;
}
