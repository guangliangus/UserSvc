using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>
/// Who the caller is allowed to be, resolved fresh from the database on every request.
/// <para>
/// Everything else in this module asks this service the question rather than reading the token,
/// because the token is an identity ticket: it says who signed in, never what they may do.
/// </para>
/// </summary>
public sealed class AdminScopeService(
    IBackOfficeUserDirectory users,
    ITenantMemberDirectory members,
    IUserTenantRoleRepository bindings,
    IRoleRepository roles,
    IRoleMenuRepository roleMenus,
    IMenuRepository menus,
    IRolePermissionRepository rolePermissions)
{
    /// <summary>
    /// The platform super-administrator flag, read from the account row.
    /// <para>
    /// An unknown id is not an error - it simply has no standing. And this is re-read every time
    /// rather than trusted from a claim, so a stale or forged token cannot escalate.
    /// </para>
    /// </summary>
    public async Task<bool> IsPlatformSuperAdminAsync(int userId, CancellationToken cancellationToken)
    {
        if (userId <= 0)
        {
            return false;
        }

        var flags = await users.FindFlagsAsync(userId, cancellationToken);
        return flags?.IsSuperAdmin ?? false;
    }

    /// <summary>
    /// Resolve everything the caller administers.
    /// </summary>
    public async Task<AdminScope> ResolveAdminScopeAsync(
        IBackOfficeCaller caller,
        CancellationToken cancellationToken)
    {
        var userId = caller.UserId;
        if (userId <= 0)
        {
            return AdminScope.Empty();
        }

        // The account-row flag decides super-administrator standing before a single membership is
        // read: it holds with zero memberships, and must short-circuit to the platform as owner.
        if (await IsPlatformSuperAdminAsync(userId, cancellationToken))
        {
            return AdminScope.ForSuperAdmin();
        }

        var memberships = await members.ListActiveByUserAsync(userId, cancellationToken);
        if (memberships.Count == 0)
        {
            return AdminScope.Empty();
        }

        var roleIdsByMember = await bindings.ListRoleIdsByMemberIdsAsync(
            [.. memberships.Select(m => m.Id)], cancellationToken);

        var allRoleIds = CallerFacts.DedupeSort(roleIdsByMember.Values.SelectMany(ids => ids));
        if (allRoleIds.Count == 0)
        {
            return AdminScope.Empty();
        }

        var roleById = (await roles.FindByIdsAsync(allRoleIds, cancellationToken))
            .ToDictionary(role => role.Id);

        var scope = AdminScope.Empty();
        foreach (var membership in memberships)
        {
            if (!roleIdsByMember.TryGetValue(membership.Id, out var boundIds))
            {
                continue;
            }

            var admins = boundIds
                .Where(roleById.ContainsKey)
                .Select(id => roleById[id])
                .Where(role => role.IsAdmin)
                .ToList();

            if (admins.Count == 0)
            {
                continue;
            }

            foreach (var role in admins)
            {
                scope.AddAdminRole(role);
            }

            var ownerType = RoleOwnerTypes.ForTenantType(membership.TenantType);
            scope.AddAdminRolesForOwner(RoleOwner.KeyFor(ownerType, membership.TenantCode), admins);

            // A whole-dimension membership lets its holder manage every tenant's members in that
            // dimension, but it owns no tenant - so it is not a candidate to own a role.
            if (membership.ScopeAll)
            {
                continue;
            }

            var owner = new RoleOwner(ownerType, membership.TenantCode);
            scope.AddOwner(owner);
            scope.AddAdminTenant(owner);
        }

        NarrowToActingContext(scope, caller);
        return scope;
    }

    /// <summary>
    /// The role-management gate (the "G4" scope), and whether it opened at all.
    /// <para>
    /// Returned as a pair rather than thrown, because one caller - "what may I do?" - needs the same
    /// narrowing without an error. Computing the flag and the owner list separately is exactly how
    /// a UI ends up offering a write path that the server then refuses.
    /// </para>
    /// </summary>
    public async Task<(AdminScope Scope, bool CanManageRoles)> ResolveRoleManageScopeAsync(
        IBackOfficeCaller caller,
        CancellationToken cancellationToken)
    {
        var scope = await ResolveAdminScopeAsync(caller, cancellationToken);
        if (scope.IsSuperAdmin)
        {
            return (scope, true);
        }

        var gated = new HashSet<int>();
        foreach (var role in scope.AdminRoles)
        {
            if (await RoleCarriesRoleManageGateAsync(role.Id, cancellationToken))
            {
                gated.Add(role.Id);
            }
        }

        var narrowed = scope.RetainRoles(gated);
        return (narrowed, narrowed.AdminRoles.Count > 0);
    }

    /// <summary>
    /// Whether one role carries both role-management signals: the roles menu <b>and</b> the role
    /// management permission point.
    /// <para>
    /// Both must sit on the <i>same</i> role. An administrator role without the roles page is a
    /// member administrator, not a role administrator, and merging the two lets the first quietly
    /// become the second.
    /// </para>
    /// </summary>
    public async Task<bool> RoleCarriesRoleManageGateAsync(int roleId, CancellationToken cancellationToken)
    {
        var menuIds = await roleMenus.ListMenuIdsByRoleIdsAsync([roleId], cancellationToken);
        if (menuIds.Count == 0)
        {
            return false;
        }

        var granted = await menus.ListByIdsAsync(menuIds, cancellationToken);
        if (!granted.Any(menu => menu.Code == IamConstants.MenuCodeUserRoles))
        {
            // No roles page: stop here rather than spend a second query proving what cannot matter.
            return false;
        }

        var permissions = await rolePermissions.ListPermissionsByRoleIdsAsync([roleId], cancellationToken);
        return permissions.Any(permission =>
            permission.Code == IamConstants.PermissionCodeRoleManage && permission.IsActive());
    }

    /// <summary>The role-management gate as a guard. Answers the narrowed scope on success.</summary>
    public async Task<AdminScope> AssertCanManageRolesAsync(
        IBackOfficeCaller caller,
        CancellationToken cancellationToken)
    {
        var (scope, canManage) = await ResolveRoleManageScopeAsync(caller, cancellationToken);
        return canManage
            ? scope
            : throw new BadRequestException(
                ErrorCodes.CallerNotAdmin,
                "Only an administrator role granted the role page may manage roles.");
    }

    /// <summary>Whether the caller administers the members of one tenant.</summary>
    public async Task AssertCanManageMembersAsync(
        IBackOfficeCaller caller,
        string tenantType,
        string tenantCode,
        CancellationToken cancellationToken)
    {
        var scope = await ResolveAdminScopeAsync(caller, cancellationToken);
        if (scope.IsSuperAdmin)
        {
            return;
        }

        var owner = new RoleOwner(RoleOwnerTypes.ForTenantType(tenantType), tenantCode);
        if (scope.AdminRolesForOwner(owner).Count > 0)
        {
            return;
        }

        throw new BadRequestException(
            ErrorCodes.CallerNotAdmin,
            "Only an administrator of this tenant may manage its members.");
    }

    /// <summary>
    /// The route-permission gate, enforced in the service rather than only on the route.
    /// <para>
    /// The API layer's attribute is the usual place for this, but an attribute is something a new
    /// route can be written without: the two catalogue reads below were open to every authenticated
    /// back-office account precisely because nothing but a doc comment named the point they needed.
    /// Asserting it here means the gate travels with the operation.
    /// </para>
    /// <para>
    /// Authority is read from the caller's resolved face, never from a token claim, and an
    /// <b>empty</b> code list denies - "required: nothing" must not read as "open to all". The
    /// super-administrator round trip happens only on the path about to refuse, so the common caller
    /// still costs one set lookup.
    /// </para>
    /// </summary>
    public async Task AssertHoldsAnyAsync(
        IBackOfficeCaller caller,
        IReadOnlyList<string> permissionCodes,
        CancellationToken cancellationToken)
    {
        if (permissionCodes.Count > 0)
        {
            var held = caller.Authz.Permissions.ToHashSet(StringComparer.Ordinal);
            if (permissionCodes.Any(held.Contains))
            {
                return;
            }
        }

        // The platform super administrator holds everything by definition rather than by grant rows,
        // so a face that has not been resolved for them must not lock them out of the catalogue.
        if (await IsPlatformSuperAdminAsync(caller.UserId, cancellationToken))
        {
            return;
        }

        throw new ForbiddenException(
            ErrorCodes.Forbidden,
            $"This operation requires one of: {string.Join(", ", permissionCodes)}.");
    }

    /// <summary>The platform-owner guard.</summary>
    public async Task AssertPlatformSuperAdminAsync(IBackOfficeCaller caller, CancellationToken cancellationToken)
    {
        if (!await IsPlatformSuperAdminAsync(caller.UserId, cancellationToken))
        {
            throw new BadRequestException(
                ErrorCodes.SuperAdminRequired,
                "Only the platform super administrator may perform this operation.");
        }
    }

    /// <summary>
    /// Granting whole-dimension access. The dimension argument exists only for symmetry at the call
    /// sites - the answer does not depend on it.
    /// <para>
    /// This is a check on platform <b>identity</b>, never on the caller's breadth. An earlier version
    /// let anyone who already held the tier hand it out, which made the tier self-replicating: one
    /// whole-dimension operator could mint unlimited peers, each passing the same gate, with no way
    /// for the platform owner to bound the population they created. The widest data grant in the
    /// system is reserved to the one identity defined as unbounded.
    /// </para>
    /// </summary>
    public Task AssertCanGrantWholeDimensionAsync(
        IBackOfficeCaller caller,
        string tenantType,
        CancellationToken cancellationToken)
    {
        _ = tenantType;
        return AssertPlatformSuperAdminAsync(caller, cancellationToken);
    }

    /// <summary>Whether the caller may create or edit roles for this role's owner.</summary>
    public static void AssertOwnerAllowed(AdminScope scope, Role role)
    {
        if (scope.IsSuperAdmin || scope.HasOwner(new RoleOwner(role.OwnerType, role.OwnerCode)))
        {
            return;
        }

        throw new BadRequestException(
            ErrorCodes.RoleOwnerNotAllowed,
            "You may not create or edit roles for this company or supplier.");
    }

    /// <summary>
    /// Refuse to hang a tenant binding on the platform super administrator.
    /// <para>
    /// That identity is exclusive: it already hard-codes every permission, every menu and global
    /// breadth in both dimensions, so memberships, roles and scope rows on the same account are never
    /// authority - only stale bindings waiting to take effect again the moment the flag is revoked.
    /// Every path that would attach one runs this against its resolved target.
    /// </para>
    /// </summary>
    public async Task AssertNotSuperAdminTargetAsync(int userId, CancellationToken cancellationToken)
    {
        var target = await users.FindFlagsAsync(userId, cancellationToken)
                     ?? throw new BadRequestException(
                         ErrorCodes.MemberNotFound, "Target user does not exist.");

        if (target.IsSuperAdmin)
        {
            throw new BadRequestException(
                ErrorCodes.SuperAdminExclusive,
                "The platform super administrator cannot hold tenant roles or company/supplier access.");
        }
    }

    /// <summary>
    /// Re-derive one membership's administrator flag from the roles bound to it.
    /// <para>
    /// The rule holds for <b>every</b> membership row, whole-dimension ones included. An earlier
    /// version forced them to false on the grounds that such a row administers no single tenant; that
    /// contradicted the data it is derived from - the platform owner's own bootstrap row is exactly a
    /// whole-dimension administrator row - so any resync silently demoted it. The flag means one
    /// thing everywhere: "this membership binds an administrator role". Nothing reads it as "an
    /// administrator of tenant X" without naming X, and the <c>*</c> sentinel matches no real tenant.
    /// </para>
    /// </summary>
    public async Task<TenantMembershipRow> SyncMemberAdminFlagAsync(
        TenantMembershipRow membership,
        IReadOnlyCollection<int> roleIds,
        CancellationToken cancellationToken)
    {
        var want = false;
        if (roleIds.Count > 0)
        {
            var bound = await roles.FindByIdsAsync(roleIds, cancellationToken);
            want = bound.Any(role => role.IsAdmin);
        }

        return await ApplyMemberAdminFlagAsync(membership, want, cancellationToken);
    }

    /// <summary>Write the flag only when it actually changes - an unchanged value is not an update.</summary>
    public async Task<TenantMembershipRow> ApplyMemberAdminFlagAsync(
        TenantMembershipRow membership,
        bool want,
        CancellationToken cancellationToken)
    {
        if (want == membership.IsAdmin)
        {
            return membership;
        }

        await members.SetAdminAsync(membership.Id, want, cancellationToken);
        return membership with { IsAdmin = want };
    }

    /// <summary>Active administrators of one tenant - the input to the last-administrator guard.</summary>
    public Task<int> CountActiveAdminsAsync(
        string tenantType,
        string tenantCode,
        CancellationToken cancellationToken) =>
        members.CountActiveAdminsAsync(tenantType, tenantCode, cancellationToken);

    private static void NarrowToActingContext(AdminScope scope, IBackOfficeCaller caller)
    {
        var (tenantType, tenantCode, isTenant) = CallerFacts.Tenant(caller);
        if (isTenant)
        {
            scope.RetainOwner(RoleOwnerTypes.ForTenantType(tenantType), tenantCode);
            return;
        }

        var dimension = CallerFacts.GlobalActDimension(caller);
        if (dimension.Length > 0)
        {
            scope.RetainDimension(RoleOwnerTypes.ForTenantType(dimension));
        }
    }
}
