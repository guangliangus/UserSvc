using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Features.BackOffice.Tenants;

/// <summary>
/// The single funnel every authority decision comes out of.
/// <para>
/// Sign-in, refresh, a context switch and the per-request authorization snapshot all call
/// <see cref="ComputeAsync"/>. That is the point: the derivation table lives in exactly one place,
/// so a rule added to it cannot apply on three paths and be missing on the fourth. The account
/// status gate below is the standing example - it used to sit in the sign-in path only, and an
/// account disabled mid-session kept every menu and permission it had until its token expired.
/// </para>
/// </summary>
public sealed class TenantContextAppService(
    ITenantMemberRepository members,
    IUserTenantRoleRepository bindings,
    IRoleDirectory roles,
    IRbacCatalog catalog,
    IAdminStandingService standing,
    IBackOfficeAccountDirectory accounts,
    ISupplierCompanyLinkDirectory supplierLinks)
{
    /// <summary>Whether this account holds whole-dimension access anywhere. The super
    /// administrator flag counts as both dimensions.</summary>
    public async Task<bool> IsGlobalUserAsync(int userId, CancellationToken cancellationToken)
    {
        var scopes = await UserScopesAsync(userId, cancellationToken);
        return scopes.Values.Any(scope => scope.IsGlobal);
    }

    /// <summary>
    /// The dimensions this account may enter wholesale, in a fixed order so the chooser and the
    /// switcher list them the same way.
    /// <para>
    /// The platform super administrator is deliberately absent: they act as PLATFORM, reach both
    /// dimensions and choose nothing at sign-in. Listing them here would show two cards to the one
    /// person who has nothing to pick between.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<string>> GlobalDimensionsAsync(
        int userId, CancellationToken cancellationToken)
    {
        var memberships = await members.ListActiveByUserAsync(userId, cancellationToken);
        var dimensions = memberships
            .Where(member => member.ScopeAll)
            .Select(member => member.TenantType)
            .ToHashSet(StringComparer.Ordinal);

        return [.. new[] { TenantTypes.Company, TenantTypes.Supplier }.Where(dimensions.Contains)];
    }

    /// <summary>
    /// Everything a context resolves to: which roles, which permissions, which menus, which data.
    /// <para>
    /// An account that is not ACTIVE answers with an <b>empty</b> context rather than an error.
    /// Empty is deliberate on both counts. An error would bounce the caller back to the sign-in
    /// page, and an account that is merely still being onboarded should not have to sign in again
    /// once it is finished. And empty means empty lists, never nulls: a null menu list serializes
    /// away, and the front end reads a missing menu claim as "this backend does not gate menus" -
    /// the exact opposite of what this gate is for.
    /// </para>
    /// </summary>
    public async Task<TenantContextResult> ComputeAsync(
        int userId, ActClaim act, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(act);

        var account = await accounts.FindAsync(userId, cancellationToken);
        if (account is null || account.Status != BackOfficeAccountStates.Active)
        {
            return TenantContextResult.NoAccess();
        }

        return act.Type switch
        {
            ActTypes.Platform => await ComputePlatformAsync(userId, cancellationToken),
            ActTypes.Global => await ComputeGlobalAsync(userId, act.Dimension, cancellationToken),
            ActTypes.Company or ActTypes.Supplier =>
                await ComputeTenantAsync(userId, act.Type, act.Code, cancellationToken),
            _ => throw new AppException(
                ErrorCodes.InternalError, $"Unknown tenant context type '{act.Type}'.", 500),
        };
    }

    /// <summary>
    /// The platform super administrator's context: everything, in both dimensions.
    /// <para>
    /// The flag is re-read from the database and the presented claim is never trusted. A token that
    /// says PLATFORM must not mint full access for an account that has since lost the flag. Losing
    /// it is a refusal rather than a downgrade, because revoking it also bumps the token version,
    /// which kills the live session outright - so in practice this branch is unreachable, and it
    /// should stay that way.
    /// </para>
    /// </summary>
    private async Task<TenantContextResult> ComputePlatformAsync(
        int userId, CancellationToken cancellationToken)
    {
        if (!await standing.IsPlatformSuperAdminAsync(userId, cancellationToken))
        {
            throw new ForbiddenException(
                ErrorCodes.TenantNotAuthorized, "This account is not the platform super administrator.");
        }

        var menus = await AllActiveMenuCodesAsync(cancellationToken);
        var permissions = await ActivePermissionCodesAsync(cancellationToken);

        return new TenantContextResult
        {
            Act = new ActClaim(ActTypes.Platform),

            // Empty, not "admin": the flag is not a role binding, and this identity is exclusive
            // with holding tenant memberships in the first place.
            Roles = [],
            Permissions = permissions,
            Menus = menus,
            Scopes = new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
            {
                [TenantTypes.Company] = ScopeClaim.Global,
                [TenantTypes.Supplier] = ScopeClaim.Global,
            },
        };
    }

    /// <summary>
    /// A whole-dimension context: every company, or every supplier.
    /// <para>
    /// The dimension chosen at sign-in narrows this to one side. Only that side's whole-dimension
    /// member rows contribute roles, and only that side's scope stays global - the other is flatten
    /// to empty, flag included. That is the isolation the choice was for: inside "all suppliers"
    /// there is no company breadth at all, so a scope-filtered query returns nothing rather than
    /// the whole platform.
    /// </para>
    /// <para>
    /// An empty dimension is a token minted before that choice existed. It keeps the old
    /// both-dimensions behaviour until it expires rather than being invalidated mid-session.
    /// </para>
    /// </summary>
    private async Task<TenantContextResult> ComputeGlobalAsync(
        int userId, string dimension, CancellationToken cancellationToken)
    {
        // The user row, not a member row. A super administrator can land here with no memberships
        // at all, so nothing below may require one to exist.
        var isSuperAdmin = await standing.IsPlatformSuperAdminAsync(userId, cancellationToken);

        var memberships = await members.ListActiveByUserAsync(userId, cancellationToken);
        var dimensionMembers = memberships
            .Where(member => member.ScopeAll)
            .Where(member => dimension.Length == 0 || member.TenantType == dimension)
            .ToList();

        IReadOnlyDictionary<int, IReadOnlyList<int>> roleIdsByMember = dimensionMembers.Count == 0
            ? new Dictionary<int, IReadOnlyList<int>>()
            : await bindings.ListRoleIdsByMemberIdsAsync(
                [.. dimensionMembers.Select(member => member.Id)], cancellationToken);

        var roleIds = roleIdsByMember.Values.SelectMany(ids => ids).Distinct().Order().ToList();
        var roleCodes = (await roles.FindByIdsAsync(roleIds, cancellationToken))
            .Select(role => role.Code)
            .Order(StringComparer.Ordinal)
            .ToList();

        var scopes = NarrowToDimension(await UserScopesAsync(userId, cancellationToken), dimension);

        IReadOnlyList<string> menus;
        IReadOnlyList<string> permissions;

        if (isSuperAdmin)
        {
            menus = await AllActiveMenuCodesAsync(cancellationToken);
            permissions = await ActivePermissionCodesAsync(cancellationToken);
        }
        else
        {
            var (menuCodes, keptMenuIds) =
                await GlobalMenuCodesAsync(dimensionMembers, roleIdsByMember, cancellationToken);
            menus = menuCodes;
            permissions = await GlobalPermissionCodesAsync(roleIds, keptMenuIds, cancellationToken);
        }

        return new TenantContextResult
        {
            Act = new ActClaim(ActTypes.Global, Dimension: dimension),
            Roles = roleCodes,
            Permissions = permissions,
            Menus = menus,
            Scopes = scopes,
        };
    }

    /// <summary>
    /// One tenant's context, resolved from that tenant's member row.
    /// </summary>
    private async Task<TenantContextResult> ComputeTenantAsync(
        int userId, string actType, string tenantCode, CancellationToken cancellationToken)
    {
        var tenantType = ActTypes.ToTenantType(actType);

        var member = await members.FindByUserAndTenantAsync(
                         userId, tenantType, tenantCode, cancellationToken)
                     ?? throw new ForbiddenException(
                         ErrorCodes.TenantNotAuthorized, "This account is not a member of this tenant.");

        // A whole-dimension row must never be resolved as a tenant. It is guarded at the selection
        // endpoint too, but this is the funnel every path comes through - refresh and the
        // per-request snapshot both arrive here with an act claim they read off a token, and an act
        // of {COMPANY, "*"} would otherwise match a scope-all row and derive a "tenant" context
        // whose data-scope envelope carries the literal sentinel as a company code. Guarding only
        // at the endpoint would leave the other three paths open.
        if (member.ScopeAll || tenantCode == TenantScopes.ScopeAllSentinelCode)
        {
            throw new ForbiddenException(
                ErrorCodes.TenantNotAuthorized,
                "A whole-dimension membership is not a tenant context.");
        }

        if (member.Status != TenantMemberStatuses.Active)
        {
            throw new ForbiddenException(
                ErrorCodes.TenantNotAuthorized, "This membership is not active.");
        }

        var roleIds = (await bindings.ListByMemberIdAsync(member.Id, cancellationToken))
            .Select(binding => binding.RoleId)
            .Distinct()
            .Order()
            .ToList();

        var roleSummaries = await roles.FindByIdsAsync(roleIds, cancellationToken);
        var roleCodes = roleSummaries.Select(role => role.Code).Order(StringComparer.Ordinal).ToList();
        var systemRoleIds = roleSummaries
            .Where(role => role.OwnerType == RoleOwnerTypes.System)
            .Select(role => role.Id)
            .ToList();

        var scopes = await TenantScopesAsync(tenantType, tenantCode, cancellationToken);

        IReadOnlyList<string> menuCodes;
        IReadOnlyList<string> permissions;

        // The platform super administrator keeps every permission in every context. Their access is
        // a hard-coded short circuit rather than a set of grants, so deriving this context purely
        // from the member row would strip them down to whatever that one membership happens to
        // grant - while every service-layer guard still answers "super administrator", and the two
        // would then disagree with the route middleware winning. Reachable whenever they are also
        // an ordinary member of some tenant.
        if (await standing.IsPlatformSuperAdminAsync(userId, cancellationToken))
        {
            var activeMenus = await catalog.ListActiveMenusAsync(cancellationToken);
            (menuCodes, _) = TenantMenuResolver.Resolve(
                [.. activeMenus.Select(menu => menu.Id)], activeMenus, tenantType);
            permissions = await ActivePermissionCodesAsync(cancellationToken);
        }
        else
        {
            var grantedMenuIds = await catalog.ListMenuIdsByRolesAsync(roleIds, cancellationToken);
            var activeMenus = await catalog.ListActiveMenusAsync(cancellationToken);
            var (codes, keptMenuIds) = TenantMenuResolver.Resolve(grantedMenuIds, activeMenus, tenantType);

            menuCodes = codes;
            permissions = await TenantPermissionCodesAsync(
                roleIds, systemRoleIds, keptMenuIds, cancellationToken);
        }

        return new TenantContextResult
        {
            // IsAdmin rides along in the act claim: it is what the shell renders administrator
            // affordances from, and recomputing it downstream would need this member row again.
            Act = new ActClaim(actType, tenantCode, string.Empty, member.IsAdmin),
            Roles = roleCodes,
            Permissions = permissions,
            Menus = menuCodes,
            Scopes = scopes,
        };
    }

    // ----------------------------------------------------------------------------- scopes

    /// <summary>
    /// The account's raw data-scope breadth, before any context narrows it: the super
    /// administrator flag becomes both dimensions global, each whole-dimension member row makes its
    /// own dimension global, and every other membership contributes its tenant code.
    /// </summary>
    private async Task<Dictionary<string, ScopeClaim>> UserScopesAsync(
        int userId, CancellationToken cancellationToken)
    {
        var isSuperAdmin = await standing.IsPlatformSuperAdminAsync(userId, cancellationToken);
        var memberships = await members.ListActiveByUserAsync(userId, cancellationToken);

        var values = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal)
        {
            [TenantTypes.Company] = new(StringComparer.Ordinal),
            [TenantTypes.Supplier] = new(StringComparer.Ordinal),
        };
        var global = new Dictionary<string, bool>(StringComparer.Ordinal)
        {
            [TenantTypes.Company] = isSuperAdmin,
            [TenantTypes.Supplier] = isSuperAdmin,
        };

        foreach (var member in memberships.Where(m => TenantTypes.IsKnown(m.TenantType)))
        {
            if (member.ScopeAll)
            {
                global[member.TenantType] = true;
                continue;
            }

            values[member.TenantType].Add(member.TenantCode);
        }

        return new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
        {
            [TenantTypes.Company] = new([.. values[TenantTypes.Company]], global[TenantTypes.Company]),
            [TenantTypes.Supplier] = new([.. values[TenantTypes.Supplier]], global[TenantTypes.Supplier]),
        };
    }

    /// <summary>
    /// Trims a raw scope envelope down to what a whole-dimension context may see.
    /// <para>
    /// Two rules, both about not leaking breadth sideways. A dimension other than the chosen one is
    /// flattened completely, global flag included. And a dimension that is <i>not</i> global keeps
    /// no values: specific tenant codes have no business inside an envelope governed by global
    /// roles, because those roles were never granted on those tenants.
    /// </para>
    /// </summary>
    private static IReadOnlyDictionary<string, ScopeClaim> NarrowToDimension(
        IReadOnlyDictionary<string, ScopeClaim> scopes, string dimension)
    {
        var narrowed = new Dictionary<string, ScopeClaim>(StringComparer.Ordinal);

        foreach (var tenantType in new[] { TenantTypes.Company, TenantTypes.Supplier })
        {
            if (dimension.Length > 0 && tenantType != dimension)
            {
                narrowed[tenantType] = ScopeClaim.None;
                continue;
            }

            var scope = scopes.GetValueOrDefault(tenantType, ScopeClaim.None);
            narrowed[tenantType] = scope.IsGlobal ? ScopeClaim.Global : ScopeClaim.None;
        }

        return narrowed;
    }

    /// <summary>
    /// A tenant context's data scope: itself, plus what hangs off it. A company also sees every
    /// supplier mounted on it; a supplier also sees the company it is mounted on, or nothing when
    /// it is independent - the conservative default, not an error.
    /// </summary>
    private async Task<IReadOnlyDictionary<string, ScopeClaim>> TenantScopesAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken)
    {
        if (tenantType == TenantTypes.Supplier)
        {
            var companyCode = await supplierLinks.FindCompanyCodeBySupplierAsync(
                tenantCode, cancellationToken);

            return new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
            {
                [TenantTypes.Company] = new(companyCode is null ? [] : [companyCode], false),
                [TenantTypes.Supplier] = new([tenantCode], false),
            };
        }

        var supplierCodes = await supplierLinks.ListSupplierCodesByCompanyAsync(
            tenantCode, cancellationToken);

        return new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
        {
            [TenantTypes.Company] = new([tenantCode], false),
            [TenantTypes.Supplier] = new([.. supplierCodes.Order(StringComparer.Ordinal)], false),
        };
    }

    // ---------------------------------------------------------------- menus and permissions

    /// <summary>
    /// Menus for a whole-dimension context, resolved <b>per dimension</b> rather than from one
    /// pooled role set.
    /// <para>
    /// "All companies" says nothing about suppliers, so company-dimension roles must not be
    /// measured against a supplier audience. This shape is kept even though the audience filter is
    /// currently off, because pooling here is what made restoring it wrong: a role bound on a
    /// global row would then grant strictly more than the same role bound on a real tenant row in
    /// its own dimension.
    /// </para>
    /// </summary>
    private async Task<(IReadOnlyList<string> Codes, IReadOnlySet<int> KeptIds)> GlobalMenuCodesAsync(
        IReadOnlyList<TenantMember> dimensionMembers,
        IReadOnlyDictionary<int, IReadOnlyList<int>> roleIdsByMember,
        CancellationToken cancellationToken)
    {
        var activeMenus = await catalog.ListActiveMenusAsync(cancellationToken);
        var codes = new SortedSet<string>(StringComparer.Ordinal);
        var keptIds = new HashSet<int>();

        foreach (var tenantType in new[] { TenantTypes.Company, TenantTypes.Supplier })
        {
            var roleIds = dimensionMembers
                .Where(member => member.TenantType == tenantType)
                .SelectMany(member => roleIdsByMember.GetValueOrDefault(member.Id, []))
                .Distinct()
                .Order()
                .ToList();

            if (roleIds.Count == 0)
            {
                continue;
            }

            var grantedMenuIds = await catalog.ListMenuIdsByRolesAsync(roleIds, cancellationToken);
            var (dimensionCodes, dimensionKept) =
                TenantMenuResolver.Resolve(grantedMenuIds, activeMenus, tenantType);

            codes.UnionWith(dimensionCodes);
            keptIds.UnionWith(dimensionKept);
        }

        return ([.. codes], keptIds);
    }

    /// <summary>
    /// Permission points for a whole-dimension context. A point whose menu did not survive falls
    /// with it - the same rule the tenant path applies - while a service-level point, which has no
    /// menu to survive, is kept.
    /// </summary>
    private async Task<IReadOnlyList<string>> GlobalPermissionCodesAsync(
        IReadOnlyList<int> roleIds,
        IReadOnlySet<int> keptMenuIds,
        CancellationToken cancellationToken)
    {
        if (roleIds.Count == 0)
        {
            return [];
        }

        var permissions = await catalog.ListPermissionsByRolesAsync(roleIds, cancellationToken);

        return [.. permissions
            .Where(permission => permission.Status == IamCatalogStatuses.Active)
            .Where(permission => permission.MenuId is not { } menuId || keptMenuIds.Contains(menuId))
            .Select(permission => permission.Code)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];
    }

    /// <summary>
    /// Permission points for a tenant context.
    /// <para>
    /// The one rule worth stating out loud: a point with no menu behind it - a service-level
    /// capability - is only granted through a SYSTEM role. A tenant's own custom role must never be
    /// able to carry one, and since such a point has no menu, the menu gate cannot be what stops
    /// it.
    /// </para>
    /// </summary>
    private async Task<IReadOnlyList<string>> TenantPermissionCodesAsync(
        IReadOnlyList<int> roleIds,
        IReadOnlyList<int> systemRoleIds,
        IReadOnlySet<int> keptMenuIds,
        CancellationToken cancellationToken)
    {
        if (roleIds.Count == 0)
        {
            return [];
        }

        var permissions = await catalog.ListPermissionsByRolesAsync(roleIds, cancellationToken);

        var systemNullMenuCodes = new HashSet<string>(StringComparer.Ordinal);
        if (systemRoleIds.Count > 0)
        {
            var systemPermissions = await catalog.ListPermissionsByRolesAsync(
                systemRoleIds, cancellationToken);

            foreach (var permission in systemPermissions.Where(p =>
                         p.Status == IamCatalogStatuses.Active && p.MenuId is null))
            {
                systemNullMenuCodes.Add(permission.Code);
            }
        }

        return [.. permissions
            .Where(permission => permission.Status == IamCatalogStatuses.Active)
            .Where(permission => permission.MenuId is { } menuId
                ? keptMenuIds.Contains(menuId)
                : systemNullMenuCodes.Contains(permission.Code))
            .Select(permission => permission.Code)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];
    }

    private async Task<IReadOnlyList<string>> AllActiveMenuCodesAsync(CancellationToken cancellationToken)
    {
        var menus = await catalog.ListActiveMenusAsync(cancellationToken);
        return [.. menus.Select(menu => menu.Code).Order(StringComparer.Ordinal)];
    }

    private async Task<IReadOnlyList<string>> ActivePermissionCodesAsync(CancellationToken cancellationToken)
    {
        var codes = await catalog.ListActivePermissionCodesAsync(cancellationToken);
        return [.. codes.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    }
}
