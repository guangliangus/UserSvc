using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac.Contracts;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>
/// The two-level grant cascade: a role is given menus, and permission points inside those menus.
/// Configuring them <b>is</b> assigning authority, so this carries the same administrator gate as
/// creating a role - a route permission alone is not enough.
/// </summary>
public sealed class RoleGrantsAppService(
    IRoleRepository roles,
    IMenuRepository menus,
    IPermissionRepository permissions,
    IRoleMenuRepository roleMenus,
    IRolePermissionRepository rolePermissions,
    IUserTenantRoleRepository bindings,
    AdminScopeService adminScopes,
    RoleVisibilityService roleVisibility,
    IamAuditWriter audit,
    IAuthzConvergence convergence,
    IUnitOfWork unitOfWork,
    ILogger<RoleGrantsAppService> logger)
{
    /// <summary>
    /// What a role effectively grants right now.
    /// <para>
    /// Only the effective set: a soft-deleted menu or point grants nothing, so echoing it back would
    /// both overstate the role and hand the configuration screen a code it cannot submit again.
    /// </para>
    /// </summary>
    public async Task<RoleGrantsResponse> GetRoleGrantsAsync(
        IBackOfficeCaller caller,
        int roleId,
        CancellationToken cancellationToken)
    {
        var role = await FindRoleAsync(roleId, cancellationToken);
        await roleVisibility.AssertRoleVisibleAsync(caller, role, mutate: false, cancellationToken);

        var grantedMenuIds = await roleMenus.ListMenuIdsByRoleIdsAsync([roleId], cancellationToken);
        var grantedMenus = (await menus.ListByIdsAsync(grantedMenuIds, cancellationToken))
            .Where(menu => menu.IsActive())
            .ToList();

        var grantedPermissions = (await rolePermissions.ListPermissionsByRoleIdsAsync([roleId], cancellationToken))
            .Where(permission => permission.IsActive())
            .ToList();

        return new RoleGrantsResponse
        {
            MenuIds = [.. grantedMenus.Select(menu => menu.Id).Order()],
            MenuCodes = [.. grantedMenus.Select(menu => menu.Code).Order(StringComparer.Ordinal)],
            PermissionIds = [.. grantedPermissions.Select(permission => permission.Id).Order()],
            PermissionCodes = [.. grantedPermissions.Select(p => p.Code).Order(StringComparer.Ordinal)],
        };
    }

    /// <summary>Replace a role's grants.</summary>
    public async Task SaveRoleGrantsAsync(
        IBackOfficeCaller caller,
        int roleId,
        SaveRoleGrantsRequest request,
        CancellationToken cancellationToken)
    {
        var role = await FindRoleAsync(roleId, cancellationToken);
        await roleVisibility.AssertRoleVisibleAsync(caller, role, mutate: true, cancellationToken);

        // Without this gate a tenant administrator could mint a child role carrying the role
        // management point and the roles menu - both inside their own ceiling, so the validator would
        // pass it - hand it to an ordinary employee, and that employee, holding no administrator role
        // at all, could rewrite role grants.
        var scope = await adminScopes.AssertCanManageRolesAsync(caller, cancellationToken);
        AssertOwnerWritable(scope, role, "configure a platform role");

        var (menuIds, menuCodes, permissionCodes) =
            await ValidateGrantsAsync(caller, role, request.MenuCodes, request.PermissionCodes, cancellationToken);

        if (role.IsAdmin)
        {
            await AssertChildrenWithinGrantsAsync(roleId, menuCodes, permissionCodes, cancellationToken);
        }

        var (beforeMenuCodes, beforePermissionCodes) = await LoadRoleGrantCodesAsync(roleId, cancellationToken);

        await unitOfWork.ExecuteInTransactionAsync(async ct =>
        {
            await roleMenus.ReplaceForRoleAsync(roleId, menuIds, AuditStamp(caller), ct);
            await rolePermissions.ReplaceForRoleAsync(roleId, permissionCodes, AuditStamp(caller), ct);
            await unitOfWork.SaveChangesAsync(ct);
        }, cancellationToken);

        await audit.WriteAsync(
            caller,
            IamAuditActions.RoleGrantsUpdate,
            IamAuditTargetTypes.Role,
            roleId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            new RoleAuditSnapshot { MenuCodes = beforeMenuCodes, PermissionCodes = beforePermissionCodes },
            new RoleAuditSnapshot { MenuCodes = menuCodes, PermissionCodes = permissionCodes },
            cancellationToken);

        await ConvergeAsync(
            roleId,
            request.ForceReissue,
            shrunk: !CallerFacts.IsSubsetOf(beforeMenuCodes, menuCodes)
                    || !CallerFacts.IsSubsetOf(beforePermissionCodes, permissionCodes),
            cancellationToken);
    }

    /// <summary>
    /// The legacy permissions-only editor. It derives the owning menu closure of the submitted points
    /// and then goes through <see cref="SaveRoleGrantsAsync"/>, which is where ownership, the cascade,
    /// the delegation subset rule, the two-table write and the audit entry all live. Without that
    /// detour, a tenant administrator reaching this route could edit a platform role.
    /// <para>
    /// It has no force-reissue field to forward and needs none: if the submitted set takes anything
    /// away, the save re-signs the bound sessions by itself, and that is the case that cannot wait.
    /// </para>
    /// </summary>
    public async Task UpdateRolePermissionsAsync(
        IBackOfficeCaller caller,
        int roleId,
        UpdateRolePermissionsRequest request,
        CancellationToken cancellationToken)
    {
        var menuCodes = await DeriveMenuClosureForPermissionsAsync(request.PermissionCodes, cancellationToken);

        await SaveRoleGrantsAsync(
            caller,
            roleId,
            new SaveRoleGrantsRequest
            {
                MenuCodes = menuCodes,
                PermissionCodes = request.PermissionCodes,
                ForceReissue = false,
            },
            cancellationToken);
    }

    /// <summary>
    /// Check a submitted grant set against every rule, and answer the resolved ids and codes.
    /// </summary>
    public async Task<(IReadOnlyList<int> MenuIds, IReadOnlyList<string> MenuCodes, IReadOnlyList<string> PermissionCodes)>
        ValidateGrantsAsync(
            IBackOfficeCaller caller,
            Role role,
            IReadOnlyList<string> requestedMenuCodes,
            IReadOnlyList<string> requestedPermissionCodes,
            CancellationToken cancellationToken)
    {
        var menuCodesIn = CallerFacts.DedupeStrings(requestedMenuCodes);
        var permissionCodesIn = CallerFacts.DedupeStrings(requestedPermissionCodes);

        var unknownMenus = new List<string>();
        var unknownPermissions = new List<string>();
        var permissionsOutsideMenus = new List<string>();
        var nullMenuPermissions = new List<string>();

        // 1. Resolve the menus. Only ACTIVE rows count; a soft-deleted menu reads as unknown.
        var activeMenuByCode = (await menus.ListByCodesAsync(menuCodesIn, cancellationToken))
            .Where(menu => menu.IsActive())
            .ToDictionary(menu => menu.Code, StringComparer.Ordinal);

        var grantedIds = new HashSet<int>();
        var grantedMenus = new List<Menu>();
        foreach (var code in menuCodesIn)
        {
            if (!activeMenuByCode.TryGetValue(code, out var menu))
            {
                unknownMenus.Add(code);
                continue;
            }

            if (grantedIds.Add(menu.Id))
            {
                grantedMenus.Add(menu);
            }
        }

        // 2. The audience rule is switched OFF here, and in the menu tree read, and in the handler's
        //    forced audience. All three or none: the read paths stopped narrowing by audience, so
        //    enforcing it on the write path alone would refuse exactly the configurations the UI
        //    presents as legal. RoleGrantViolations.AudienceViolations therefore never fills.
        //    To restore it, re-enable all three sites together, and first list what would start being
        //    refused - today's data already contains violators:
        //      SELECT r.code, r.owner_type, m.code, m.audience
        //      FROM iam.role_menus rm
        //      JOIN iam.roles r ON r.id = rm.role_id
        //      JOIN iam.menus m ON m.id = rm.menu_id
        //      WHERE r.owner_type <> 'SYSTEM'
        //        AND NOT (m.audience @> to_jsonb(lower(r.owner_type)));
        //    The check itself: for each granted menu, menu.ParseAudience() must contain
        //    RoleOwnerTypes.ToTenantType(role.OwnerType) whenever the role is tenant-owned.

        // 3. Granting a child implies granting its parent - refused, never auto-completed. Silently
        //    widening a submission is how an operator ends up having given away a menu they never
        //    ticked.
        var missingParentIds = grantedMenus
            .Where(menu => menu.ParentId is not null && !grantedIds.Contains(menu.ParentId!.Value))
            .Select(menu => menu.ParentId!.Value)
            .Distinct()
            .ToList();

        var missingParentMenus = missingParentIds.Count == 0
            ? []
            : (await menus.ListByIdsAsync(missingParentIds, cancellationToken))
                .Select(menu => menu.Code)
                .Order(StringComparer.Ordinal)
                .ToList();

        // 4. Resolve the permission points, again ACTIVE only.
        var activePermissionByCode = (await permissions.ListByCodesAsync(permissionCodesIn, cancellationToken))
            .Where(permission => permission.IsActive())
            .ToDictionary(permission => permission.Code, StringComparer.Ordinal);

        var outPermissionCodes = new List<string>();
        foreach (var code in permissionCodesIn)
        {
            if (!activePermissionByCode.TryGetValue(code, out var permission))
            {
                unknownPermissions.Add(code);
                continue;
            }

            if (permission.MenuId is null)
            {
                // A service-level point belongs to no menu and never appears in the tenant permission
                // tree, so only a platform role may carry one.
                if (role.OwnerType != RoleOwnerTypes.System)
                {
                    nullMenuPermissions.Add(code);
                }
                else
                {
                    outPermissionCodes.Add(code);
                }

                continue;
            }

            if (!grantedIds.Contains(permission.MenuId.Value))
            {
                permissionsOutsideMenus.Add(code);
                continue;
            }

            outPermissionCodes.Add(code);
        }

        // 5. Subset of the creator, for tenant callers only. The ceiling is the caller's live
        //    authorization face rather than anything in their token: a menu taken away from them stops
        //    being delegable on their very next request. Platform and whole-dimension callers are
        //    exempt - they are not delegating from within a tenant.
        var menusNotDelegable = new List<string>();
        var permissionsNotDelegable = new List<string>();
        var (_, _, isTenant) = CallerFacts.Tenant(caller);
        if (isTenant)
        {
            var heldMenus = caller.Authz.Menus.ToHashSet(StringComparer.Ordinal);
            var heldPermissions = caller.Authz.Permissions.ToHashSet(StringComparer.Ordinal);

            menusNotDelegable.AddRange(menuCodesIn.Where(code => !heldMenus.Contains(code)));
            permissionsNotDelegable.AddRange(permissionCodesIn.Where(code => !heldPermissions.Contains(code)));
        }

        var violations = new RoleGrantViolations
        {
            UnknownMenus = unknownMenus,
            UnknownPermissions = unknownPermissions,
            MissingParentMenus = missingParentMenus,
            PermissionsOutsideMenus = permissionsOutsideMenus,
            NullMenuPermissions = nullMenuPermissions,
            MenusNotDelegable = menusNotDelegable,
            PermissionsNotDelegable = permissionsNotDelegable,
        };

        if (!violations.IsEmpty)
        {
            throw new RoleGrantViolationException(
                ErrorCodes.MenuNotGranted, "Role grants violate the menu cascade.", violations);
        }

        var grantedMenuCodes = grantedMenus.Select(menu => menu.Code).Order(StringComparer.Ordinal).ToList();
        outPermissionCodes.Sort(StringComparer.Ordinal);

        // 6. A child role may never grant more than its group leader. Checked last, so the more
        //    specific cascade failures keep their own error code and this one is reported on its own.
        if (role.ParentRoleId is not null)
        {
            var parent = await roles.FindByIdAsync(role.ParentRoleId.Value, cancellationToken);
            var (ceilingMenus, ceilingPermissions) = await RoleGrantCeilingAsync(parent, cancellationToken);

            var beyondMenus = grantedMenuCodes.Where(code => !ceilingMenus.Contains(code))
                .Order(StringComparer.Ordinal).ToList();
            var beyondPermissions = outPermissionCodes.Where(code => !ceilingPermissions.Contains(code))
                .Order(StringComparer.Ordinal).ToList();

            if (beyondMenus.Count > 0 || beyondPermissions.Count > 0)
            {
                throw new RoleGrantViolationException(
                    ErrorCodes.RoleGrantsExceedParent,
                    "Role grants exceed the parent administrator role.",
                    new RoleGrantViolations
                    {
                        BeyondParentMenus = beyondMenus,
                        BeyondParentPermissions = beyondPermissions,
                    });
            }
        }

        return (
            [.. grantedMenus.Select(menu => menu.Id).Order()],
            grantedMenuCodes,
            outPermissionCodes);
    }

    /// <summary>
    /// A parent administrator role's ceiling: every menu and permission code it carries.
    /// <b>Unfiltered by status</b> on purpose - this is a bound, not a grant.
    /// </summary>
    public async Task<(HashSet<string> Menus, HashSet<string> Permissions)> RoleGrantCeilingAsync(
        Role? parent,
        CancellationToken cancellationToken)
    {
        if (parent is null)
        {
            return ([], []);
        }

        var menuIds = await roleMenus.ListMenuIdsByRoleIdsAsync([parent.Id], cancellationToken);
        var ceilingMenus = (await menus.ListByIdsAsync(menuIds, cancellationToken))
            .Select(menu => menu.Code)
            .ToHashSet(StringComparer.Ordinal);

        var ceilingPermissions = (await rolePermissions.ListPermissionsByRoleIdsAsync([parent.Id], cancellationToken))
            .Select(permission => permission.Code)
            .ToHashSet(StringComparer.Ordinal);

        return (ceilingMenus, ceilingPermissions);
    }

    /// <summary>
    /// Keep the ceiling intact across a <b>re-parent</b>.
    /// <para>
    /// The child check guards only the other direction - shrinking a leader below its children. Moving
    /// a child under a narrower leader breaks the same invariant just as quietly, and from then on the
    /// grant validator measures the role against a ceiling it already exceeds.
    /// </para>
    /// </summary>
    public async Task AssertGrantsWithinNewParentAsync(
        Role role,
        int? newParentId,
        CancellationToken cancellationToken)
    {
        if (newParentId is null || role.ParentRoleId == newParentId)
        {
            return;
        }

        var parent = await roles.FindByIdAsync(newParentId.Value, cancellationToken);
        var (ceilingMenus, ceilingPermissions) = await RoleGrantCeilingAsync(parent, cancellationToken);
        var (menuCodes, permissionCodes) = await LoadRoleGrantCodesAsync(role.Id, cancellationToken);

        var beyondMenus = menuCodes.Where(code => !ceilingMenus.Contains(code)).ToList();
        var beyondPermissions = permissionCodes.Where(code => !ceilingPermissions.Contains(code)).ToList();

        if (beyondMenus.Count == 0 && beyondPermissions.Count == 0)
        {
            return;
        }

        throw new RoleGrantViolationException(
            ErrorCodes.RoleGrantsExceedParent,
            "The role's current grants exceed the new parent administrator role.",
            new RoleGrantViolations
            {
                BeyondParentMenus = beyondMenus,
                BeyondParentPermissions = beyondPermissions,
            });
    }

    /// <summary>
    /// Refuse to shrink a leader below what its children already grant.
    /// <para>
    /// "A child never exceeds its parent" has to hold at every instant, and quietly trimming the
    /// children behind the operator's back is not an option. Note the detail shape here is a plain
    /// role list, unlike the validator's violation buckets: the two answer different questions.
    /// </para>
    /// </summary>
    public async Task AssertChildrenWithinGrantsAsync(
        int roleId,
        IReadOnlyList<string> menuCodes,
        IReadOnlyList<string> permissionCodes,
        CancellationToken cancellationToken)
    {
        var children = await roles.ListChildrenAsync([roleId], cancellationToken);
        if (children.Count == 0)
        {
            return;
        }

        var menuSet = menuCodes.ToHashSet(StringComparer.Ordinal);
        var permissionSet = permissionCodes.ToHashSet(StringComparer.Ordinal);

        var offending = new List<string>();
        foreach (var child in children)
        {
            var (childMenus, childPermissions) = await LoadRoleGrantCodesAsync(child.Id, cancellationToken);
            if (childMenus.Any(code => !menuSet.Contains(code))
                || childPermissions.Any(code => !permissionSet.Contains(code)))
            {
                offending.Add(child.Code);
            }
        }

        if (offending.Count > 0)
        {
            throw new RoleSetException(
                ErrorCodes.RoleGrantsExceedParent,
                "Child roles would be left with grants outside this administrator role.",
                [.. offending.Order(StringComparer.Ordinal)]);
        }
    }

    /// <summary>
    /// A role's current <b>effective</b> menu and permission codes, sorted.
    /// <para>
    /// Effective, not stored. A stale row pointing at a soft-deleted menu must not count as "held"
    /// anywhere it is compared: its code cannot pass validation, so counting it would make the child
    /// check and the re-parent ceiling permanently unsatisfiable, and would make every save look like
    /// a revocation and bump token versions for nothing.
    /// </para>
    /// </summary>
    public async Task<(IReadOnlyList<string> MenuCodes, IReadOnlyList<string> PermissionCodes)>
        LoadRoleGrantCodesAsync(int roleId, CancellationToken cancellationToken)
    {
        var menuIds = await roleMenus.ListMenuIdsByRoleIdsAsync([roleId], cancellationToken);
        var menuCodes = (await menus.ListByIdsAsync(menuIds, cancellationToken))
            .Where(menu => menu.IsActive())
            .Select(menu => menu.Code)
            .Order(StringComparer.Ordinal)
            .ToList();

        var permissionCodes = (await rolePermissions.ListPermissionsByRoleIdsAsync([roleId], cancellationToken))
            .Where(permission => permission.IsActive())
            .Select(permission => permission.Code)
            .Order(StringComparer.Ordinal)
            .ToList();

        return (menuCodes, permissionCodes);
    }

    /// <summary>
    /// The menu codes implied by a set of permission points: each point's owning menu and every
    /// ancestor of it. Unknown and service-level points contribute nothing - accepting or refusing
    /// them is the grant validator's job.
    /// </summary>
    public async Task<IReadOnlyList<string>> DeriveMenuClosureForPermissionsAsync(
        IReadOnlyList<string> permissionCodes,
        CancellationToken cancellationToken)
    {
        if (permissionCodes.Count == 0)
        {
            return [];
        }

        var resolved = await permissions.ListByCodesAsync(permissionCodes, cancellationToken);
        var menuIds = resolved
            .Where(permission => permission.IsActive() && permission.MenuId is not null)
            .Select(permission => permission.MenuId!.Value)
            .ToHashSet();

        if (menuIds.Count == 0)
        {
            return [];
        }

        var byId = (await menus.ListActiveAsync(cancellationToken)).ToDictionary(menu => menu.Id);
        var codes = new HashSet<string>(StringComparer.Ordinal);

        foreach (var menuId in menuIds)
        {
            var current = (int?)menuId;
            while (current is not null && byId.TryGetValue(current.Value, out var menu))
            {
                if (!codes.Add(menu.Code))
                {
                    break;
                }

                current = menu.ParentId;
            }
        }

        return [.. codes.Order(StringComparer.Ordinal)];
    }

    /// <summary>
    /// Make the change reach sessions that are already open.
    /// <para>
    /// A revocation converges by itself - waiting for an operator to tick "force reissue" would leave
    /// a removed point usable for the rest of every unexpired token's life. Growth does not need a
    /// reissue: the new grants arrive on the next natural refresh, and re-signing every bound member's
    /// session for a purely additive change is churn. Either way the cached authorization faces go, so
    /// even an addition takes effect on the members' next request.
    /// </para>
    /// </summary>
    private async Task ConvergeAsync(
        int roleId,
        bool forceReissue,
        bool shrunk,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<int> userIds;
        try
        {
            userIds = CallerFacts.DedupeSort(await bindings.ListUserIdsByRoleIdAsync(roleId, cancellationToken));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The grants are committed. Failing here would report an error for a change that took.
            logger.LogWarning(ex, "Could not list members bound to role {RoleId}; their sessions will converge on expiry.", roleId);
            return;
        }

        if (userIds.Count == 0)
        {
            return;
        }

        try
        {
            if (forceReissue || shrunk)
            {
                await convergence.BumpTokenVersionAsync(userIds, cancellationToken);
            }
            else
            {
                await convergence.InvalidateAuthzAsync(userIds, cancellationToken);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Could not converge sessions after a grant change on role {RoleId}.", roleId);
        }
    }

    private async Task<Role> FindRoleAsync(int roleId, CancellationToken cancellationToken) =>
        await roles.FindByIdAsync(roleId, cancellationToken)
        ?? throw new NotFoundException(ErrorCodes.NotFound, "Role was not found.");

    private static void AssertOwnerWritable(AdminScope scope, Role role, string what)
    {
        if (role.OwnerType == RoleOwnerTypes.System)
        {
            // Same shape as the edit and delete paths, so the UI sees one code for "this is a platform
            // role and you are not the platform owner". A GLOBAL caller slips past the visibility
            // check, which only narrows tenant contexts; this branch is what actually stops them.
            if (!scope.IsSuperAdmin)
            {
                throw new BadRequestException(
                    ErrorCodes.SuperAdminRequired,
                    $"Only the platform super administrator may {what}.");
            }

            return;
        }

        AdminScopeService.AssertOwnerAllowed(scope, role);
    }

    /// <summary>The audit stamp written to <c>created_by</c>: the acting account and its display
    /// name, so a row can be traced to a person after a rename.</summary>
    private static string? AuditStamp(IBackOfficeCaller caller) =>
        caller.UserId <= 0 ? null : $"{caller.UserId}:{caller.Nickname}";
}

/// <summary>A grant refusal carrying the full violation breakdown as problem extensions.</summary>
public sealed class RoleGrantViolationException(
    string errorCode,
    string message,
    RoleGrantViolations violations)
    : AppException(errorCode, message, 400)
{
    /// <summary>Which rules fired, bucketed.</summary>
    public RoleGrantViolations Violations { get; } = violations;
}
