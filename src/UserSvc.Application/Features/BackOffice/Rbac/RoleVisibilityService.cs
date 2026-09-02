using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>
/// Which roles a caller may see, and which they may open. The role list endpoint carries no route
/// permission at all - this service is the whole of its confidentiality.
/// </summary>
public sealed class RoleVisibilityService(
    AdminScopeService adminScopes,
    ActiveUserRoleReader activeRoles)
{
    /// <summary>
    /// The ids this caller may see, or <c>null</c> for "unrestricted". The <c>catalogue</c> must be
    /// the <b>full</b> one, because the parent chain has to be walked through roles the caller cannot
    /// see.
    /// </summary>
    public async Task<HashSet<int>?> ResolveVisibleRoleIdsAsync(
        IBackOfficeCaller caller,
        IReadOnlyList<Role> catalogue,
        CancellationToken cancellationToken)
    {
        var userId = caller.UserId;
        if (userId <= 0)
        {
            // Not "unrestricted". A narrowing read that treats an absent caller as the platform is
            // precisely how this endpoint would turn into a platform-wide role directory.
            return [];
        }

        var scope = await adminScopes.ResolveAdminScopeAsync(caller, cancellationToken);
        if (scope.IsSuperAdmin)
        {
            return null;
        }

        // Dimension lock: only the roles held through memberships on the side the caller signed in
        // as. Seeing a role you hold is not a leak, but showing the same page in both contexts split
        // this endpoint away from every other one, all of which are dimension-locked.
        var dimension = CallerFacts.ActDimension(caller);
        var own = await activeRoles.ListRolesAsync(userId, dimension, cancellationToken);

        var visible = new HashSet<int>();
        var childrenByParent = catalogue
            .Where(role => role.ParentRoleId is not null)
            .GroupBy(role => role.ParentRoleId!.Value)
            .ToDictionary(group => group.Key, group => group.ToList());

        // (1) The roles the caller holds.
        var frontier = new Queue<int>();
        var seen = new HashSet<int>();
        foreach (var role in own)
        {
            visible.Add(role.Id);
            if (seen.Add(role.Id))
            {
                frontier.Enqueue(role.Id);
            }
        }

        // (2) Roles filed underneath them - but only the platform-owned ones. Every group leader is
        // platform-owned by construction, so a seeded leader such as company_admin is held by every
        // company's administrator; revealing a tenant-owned descendant merely because it hangs under
        // a shared leader would show one company's roles to another. Tenant-owned descendants stay
        // reachable to their own tenant through (3). The walk continues through them regardless, so a
        // future tenant-owned leader cannot silently hide an entire subtree. The seen set doubles as
        // the cycle guard.
        while (frontier.Count > 0)
        {
            var parentId = frontier.Dequeue();
            if (!childrenByParent.TryGetValue(parentId, out var children))
            {
                continue;
            }

            foreach (var child in children)
            {
                if (!child.IsTenantOwned())
                {
                    visible.Add(child.Id);
                }

                if (seen.Add(child.Id))
                {
                    frontier.Enqueue(child.Id);
                }
            }
        }

        // (3) Roles owned by the caller's own company or supplier - the tenants their scope envelope
        // names. Whole-dimension breadth deliberately does not widen this: an "all companies"
        // operator is not the platform owner, so their role page is their own roles plus the group
        // beneath them, not every company's private roles.
        var companyScope = caller.Authz.ScopeFor(TenantTypes.Company);
        var supplierScope = caller.Authz.ScopeFor(TenantTypes.Supplier);

        // The dimension lock applies here too. A company context's envelope carries the suppliers
        // mounted to that company, so leaving it in would let a company sign-in reach those
        // suppliers' own roles through (3) - contradicting the lock the other two clauses obey.
        if (dimension == TenantTypes.Company)
        {
            supplierScope = ScopeClaim.Empty;
        }
        else if (dimension == TenantTypes.Supplier)
        {
            companyScope = ScopeClaim.Empty;
        }

        foreach (var role in catalogue.Where(role => !visible.Contains(role.Id)))
        {
            var covered = role.OwnerType switch
            {
                RoleOwnerTypes.Company => CallerFacts.ScopeCoversOwnerCode(companyScope, role.OwnerCode),
                RoleOwnerTypes.Supplier => CallerFacts.ScopeCoversOwnerCode(supplierScope, role.OwnerCode),
                _ => false,
            };

            if (covered)
            {
                visible.Add(role.Id);
            }
        }

        return visible;
    }

    /// <summary>
    /// Whether this caller may edit this role, measured against the <b>narrowed</b> role-management
    /// scope - an owner whose administrator roles lack the role page is not a writable owner.
    /// </summary>
    public static bool RoleWritableByScope(AdminScope? scope, Role role)
    {
        if (scope is null)
        {
            return false;
        }

        if (scope.IsSuperAdmin)
        {
            return true;
        }

        return role.IsTenantOwned() && scope.HasOwner(new RoleOwner(role.OwnerType, role.OwnerCode));
    }

    /// <summary>
    /// The per-role ownership check on both reads and writes.
    /// <para>
    /// Writes (<c>mutate</c>) stay a strict per-tenant comparison. Reads measure ownership against the
    /// caller's scope envelope instead - the same rule the role list uses - because a company context
    /// carries the suppliers mounted to it, and comparing only against the single acting tenant code
    /// would list a role and then refuse to open it.
    /// </para>
    /// </summary>
    public async Task AssertRoleVisibleAsync(
        IBackOfficeCaller caller,
        Role role,
        bool mutate,
        CancellationToken cancellationToken)
    {
        var (tenantType, tenantCode, isTenant) = CallerFacts.Tenant(caller);

        if (!isTenant)
        {
            // Absent claims, PLATFORM, or GLOBAL. A GLOBAL caller is not the platform: that context
            // is where every whole-dimension holder lands, and its act claim does not even say which
            // dimension its rows cover. On a read, a tenant-owned role opens only when the caller's
            // own envelope covers its owner - otherwise the list's "visible but unopenable" flips
            // into "invisible but openable", and a company-side operator could pull a supplier
            // tenant's whole configuration through the grants endpoint.
            if (!mutate && role.IsTenantOwned() && !RoleOwnerInCallerScopes(caller, role))
            {
                await RefuseUnlessSuperAdminAsync(caller, "Role belongs to another tenant.", cancellationToken);
            }

            return;
        }

        if (role.OwnerType == RoleOwnerTypes.System)
        {
            if (mutate)
            {
                await RefuseUnlessSuperAdminAsync(caller, "Cannot edit a system role.", cancellationToken);
            }

            return;
        }

        if (mutate)
        {
            if (!role.IsOwnedBy(tenantType, tenantCode))
            {
                await RefuseUnlessSuperAdminAsync(caller, "Role belongs to another tenant.", cancellationToken);
            }

            return;
        }

        if (!RoleOwnerInCallerScopes(caller, role))
        {
            await RefuseUnlessSuperAdminAsync(caller, "Role belongs to another tenant.", cancellationToken);
        }
    }

    /// <summary>Whether the caller's acting dimension's scope envelope names this role's owner.</summary>
    public static bool RoleOwnerInCallerScopes(IBackOfficeCaller caller, Role role) => caller.ActType switch
    {
        ActTypes.Company => CallerFacts.ScopeCoversOwnerCode(
            caller.Authz.ScopeFor(TenantTypes.Company), role.OwnerCode),
        ActTypes.Supplier => CallerFacts.ScopeCoversOwnerCode(
            caller.Authz.ScopeFor(TenantTypes.Supplier), role.OwnerCode),
        _ => false,
    };

    /// <summary>
    /// Refuse with 403, unless the caller turns out to be the platform super administrator.
    /// <para>
    /// This is the tail of a claims-only pre-check, so the database round trip that establishes
    /// super-administrator standing happens <b>only on the path about to refuse</b>: the common
    /// tenant caller still costs nothing.
    /// </para>
    /// </summary>
    public async Task RefuseUnlessSuperAdminAsync(
        IBackOfficeCaller caller,
        string message,
        CancellationToken cancellationToken)
    {
        if (await adminScopes.IsPlatformSuperAdminAsync(caller.UserId, cancellationToken))
        {
            return;
        }

        throw new ForbiddenException(ErrorCodes.Forbidden, message);
    }
}
