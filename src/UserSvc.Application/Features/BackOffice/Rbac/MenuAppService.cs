using System.Globalization;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac.Contracts;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>
/// The menu registry: the sidebar's shape, and the skeleton every permission point hangs from.
/// <para>
/// All three mutations re-assert the platform super administrator inside the service. The route's
/// permission point is an ordinary one that can be hung on any role, and this registry decides where
/// permission points can exist - the same belt-and-braces the permission catalogue gets.
/// </para>
/// </summary>
public sealed class MenuAppService(
    IMenuRepository menus,
    IPermissionRepository permissions,
    AdminScopeService adminScopes,
    IamAuditWriter audit,
    IUnitOfWork unitOfWork,
    IClock clock)
{
    /// <summary>
    /// The management tree, with each menu's permission points under it.
    /// </summary>
    /// <param name="caller">Who is asking; the gate reads their resolved permission face.</param>
    /// <param name="audience">
    /// Accepted and echoed on every node, but <b>completely inert</b>: audience filtering was switched
    /// off here, in the grant validator and in the API layer's forced audience, together.
    /// <para>
    /// The catalogue declares the resource and supplier menus as platform+supplier, while the role
    /// granted exactly those menus is also bound to company members - so filtering made a role's main
    /// menus vanish from the role detail view with no explanation. This was only ever a visibility
    /// narrowing, never an authorisation boundary: route access is decided by permission code, which
    /// this never touched.
    /// </para>
    /// <para>
    /// To restore: skip any menu whose <see cref="Menu.ParseAudience"/> does not contain the requested
    /// audience, re-enable the same rule in the grant validator, and re-enable the API layer forcing
    /// the audience from the caller's acting type (COMPANY to company, SUPPLIER to supplier, anything
    /// else unforced).
    /// </para>
    /// </param>
    /// <param name="status">Empty means every status. Naming one filters the menus <b>and</b> the
    /// points under them: an ACTIVE tree feeds the role grant editor, and an INACTIVE point offered
    /// there would only be refused as unknown when the form is submitted.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    public async Task<MenuTreeResponse> GetMenuTreeAsync(
        IBackOfficeCaller caller,
        string? audience,
        string? status,
        CancellationToken cancellationToken)
    {
        _ = audience;

        // Either point opens it, matching the pair on a role's grants: a grant payload is unreadable
        // without the names of the menus it points at. Asserted here rather than only on the route,
        // because this tree is the registry every permission point hangs from.
        await adminScopes.AssertHoldsAnyAsync(
            caller,
            [IamConstants.PermissionCodeRoleManage, IamConstants.PermissionCodeMemberRead],
            cancellationToken);

        var all = await menus.ListAllAsync(cancellationToken);
        var kept = string.IsNullOrEmpty(status)
            ? all
            : [.. all.Where(menu => menu.Status == status)];

        if (kept.Count == 0)
        {
            return new MenuTreeResponse();
        }

        var keptIds = kept.Select(menu => menu.Id).ToHashSet();
        var points = await permissions.ListByMenuIdsAsync([.. keptIds], cancellationToken);

        var pointsByMenu = points
            .Where(point => point.MenuId is not null)
            .Where(point => string.IsNullOrEmpty(status) || point.Status == status)
            .GroupBy(point => point.MenuId!.Value)
            .ToDictionary(group => group.Key, group => (IReadOnlyList<Permission>)[.. group]);

        return new MenuTreeResponse
        {
            Items = BuildTree(kept, keptIds, pointsByMenu),
        };
    }

    /// <summary>
    /// One user's sidebar: only the menus they were granted, and never an INACTIVE one.
    /// </summary>
    public async Task<MenuTreeResponse> GetGrantedMenuTreeAsync(
        IReadOnlyList<string> grantedCodes,
        CancellationToken cancellationToken)
    {
        var granted = grantedCodes.ToHashSet(StringComparer.Ordinal);
        var active = await menus.ListActiveAsync(cancellationToken);
        var kept = active.Where(menu => granted.Contains(menu.Code)).ToList();

        if (kept.Count == 0)
        {
            return new MenuTreeResponse();
        }

        // The parent chain is built over ALL active menus, not just the granted ones: a granted node
        // whose immediate parent is not granted must re-attach to its nearest granted ancestor rather
        // than be promoted to a root, which would flatten the hierarchy.
        var parentById = active.ToDictionary(menu => menu.Id, menu => menu.ParentId);
        var keptIds = kept.Select(menu => menu.Id).ToHashSet();

        var childrenByParent = new Dictionary<int, List<Menu>>();
        var roots = new List<Menu>();

        foreach (var menu in kept)
        {
            var ancestor = NearestGrantedAncestor(menu.Id, parentById, keptIds);
            if (ancestor is null)
            {
                roots.Add(menu);
                continue;
            }

            if (!childrenByParent.TryGetValue(ancestor.Value, out var bucket))
            {
                bucket = [];
                childrenByParent[ancestor.Value] = bucket;
            }

            bucket.Add(menu);
        }

        // The sidebar tree carries no permission points.
        var empty = new Dictionary<int, IReadOnlyList<Permission>>();
        return new MenuTreeResponse
        {
            Items = [.. roots.Select(root => BuildNode(root, childrenByParent, empty))],
        };
    }

    /// <summary>Register a menu.</summary>
    public async Task<MenuResponse> CreateMenuAsync(
        IBackOfficeCaller caller,
        CreateMenuRequest request,
        CancellationToken cancellationToken)
    {
        await adminScopes.AssertPlatformSuperAdminAsync(caller, cancellationToken);

        ValidateMenuName(request.Name);
        var audience = NormalizeAudience(request.Audience);
        var status = NormalizeStatus(request.Status);

        if (await menus.FindByCodeAsync(request.Code, cancellationToken) is not null)
        {
            throw new ConflictException(ErrorCodes.BadRequest, "Menu code already exists.");
        }

        if (request.ParentId is not null
            && await menus.FindByIdAsync(request.ParentId.Value, cancellationToken) is null)
        {
            throw new BadRequestException(ErrorCodes.BadRequest, "Parent menu not found.");
        }

        var now = clock.UtcNow;
        var menu = new Menu
        {
            Code = request.Code,
            ParentId = request.ParentId,
            Name = Menu.BuildName(request.Name),
            Path = request.Path,
            Icon = request.Icon,
            SortOrder = request.SortOrder,
            Audience = Menu.BuildAudience(audience),
            Status = status,
            CreatedAt = now,
            UpdatedAt = now,
            CreatedBy = AuditStamp(caller),
            UpdatedBy = AuditStamp(caller),
        };

        menus.Add(menu);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return ToResponse(menu);
    }

    /// <summary>Edit a menu. Code and parent are immutable and are not read from the request.</summary>
    public async Task<MenuResponse> UpdateMenuAsync(
        IBackOfficeCaller caller,
        int menuId,
        UpdateMenuRequest request,
        CancellationToken cancellationToken)
    {
        await adminScopes.AssertPlatformSuperAdminAsync(caller, cancellationToken);

        ValidateMenuName(request.Name);
        var audience = NormalizeAudience(request.Audience);
        var status = NormalizeStatus(request.Status);

        var menu = await menus.FindByIdAsync(menuId, cancellationToken)
                   ?? throw new NotFoundException(ErrorCodes.NotFound, "Menu was not found.");

        menu.Name = Menu.BuildName(request.Name);
        menu.Path = request.Path;
        menu.Icon = request.Icon;
        menu.SortOrder = request.SortOrder;
        menu.Audience = Menu.BuildAudience(audience);
        menu.Status = status;
        menu.UpdatedAt = clock.UtcNow;
        menu.UpdatedBy = AuditStamp(caller);

        await unitOfWork.SaveChangesAsync(cancellationToken);
        return ToResponse(menu);
    }

    /// <summary>
    /// Remove a menu and the permission points on it.
    /// <para>
    /// Roles granted this menu simply lose it, and the members holding those roles converge when their
    /// authorization face is next resolved - the same convergence a grant edit relies on.
    /// </para>
    /// </summary>
    public async Task DeleteMenuAsync(
        IBackOfficeCaller caller,
        int menuId,
        CancellationToken cancellationToken)
    {
        await adminScopes.AssertPlatformSuperAdminAsync(caller, cancellationToken);

        var menu = await menus.FindByIdAsync(menuId, cancellationToken)
                   ?? throw new NotFoundException(ErrorCodes.NotFound, "Menu was not found.");

        if ((await menus.ListChildrenAsync(menuId, cancellationToken)).Count > 0)
        {
            throw new ConflictException(ErrorCodes.MenuHasChildren, "Menu still has child menus.");
        }

        // Captured before the delete: the audit trail has to name the permission points that went
        // offline with the menu, and afterwards there is nothing left to read.
        var permissionCodes = (await permissions.ListByMenuIdsAsync([menuId], cancellationToken))
            .Select(permission => permission.Code)
            .Order(StringComparer.Ordinal)
            .ToList();

        await unitOfWork.ExecuteInTransactionAsync(async ct =>
        {
            // Order is not interchangeable: permissions.menu_id is ON DELETE RESTRICT. The grant rows
            // on both sides cascade in the database.
            await permissions.DeleteByMenuIdAsync(menuId, ct);
            menus.Remove(menu);
            await unitOfWork.SaveChangesAsync(ct);
        }, cancellationToken);

        await audit.WriteAsync(
            caller,
            IamAuditActions.MenuDelete,
            IamAuditTargetTypes.Menu,
            menuId.ToString(CultureInfo.InvariantCulture),
            new MenuAuditSnapshot
            {
                Code = menu.Code,
                Path = menu.Path,
                Status = menu.Status,
                PermissionCodes = permissionCodes.Count > 0 ? permissionCodes : null,
            },
            after: null,
            cancellationToken);
    }

    /// <summary>A menu nobody can read a label for is not a menu.</summary>
    private static void ValidateMenuName(IReadOnlyDictionary<string, string> name)
    {
        if (name.Count == 0)
        {
            throw new BadRequestException(ErrorCodes.BadRequest, "Name must contain at least one locale.");
        }
    }

    /// <summary>Empty means all three tenant types; anything outside the closed set is refused by
    /// name so the operator knows which value was wrong.</summary>
    private static IReadOnlyList<string> NormalizeAudience(IReadOnlyList<string> requested)
    {
        if (requested.Count == 0)
        {
            return MenuAudiences.All;
        }

        var result = new List<string>(requested.Count);
        foreach (var value in requested)
        {
            if (!MenuAudiences.IsValid(value))
            {
                throw new BadRequestException(ErrorCodes.BadRequest, $"Invalid audience value: {value}.");
            }

            if (!result.Contains(value))
            {
                result.Add(value);
            }
        }

        return result;
    }

    private static string NormalizeStatus(string? requested)
    {
        if (string.IsNullOrEmpty(requested))
        {
            return MenuStatuses.Active;
        }

        return MenuStatuses.IsValid(requested)
            ? requested
            : throw new BadRequestException(ErrorCodes.BadRequest, $"Invalid status: {requested}.");
    }

    private static int? NearestGrantedAncestor(
        int menuId,
        IReadOnlyDictionary<int, int?> parentById,
        IReadOnlySet<int> granted)
    {
        var current = parentById.TryGetValue(menuId, out var parent) ? parent : null;
        var guard = 0;

        while (current is not null && guard++ < IamConstants.MaxRoleSubtreeDepth)
        {
            if (granted.Contains(current.Value))
            {
                return current;
            }

            current = parentById.TryGetValue(current.Value, out var next) ? next : null;
        }

        return null;
    }

    /// <summary>Nest the kept rows. A node whose parent was filtered out is <b>promoted to a
    /// root</b> so its branch still renders instead of disappearing with its parent.</summary>
    private static IReadOnlyList<MenuTreeNodeResponse> BuildTree(
        IReadOnlyList<Menu> kept,
        IReadOnlySet<int> keptIds,
        IReadOnlyDictionary<int, IReadOnlyList<Permission>> pointsByMenu)
    {
        var childrenByParent = new Dictionary<int, List<Menu>>();
        var roots = new List<Menu>();

        foreach (var menu in kept)
        {
            if (menu.ParentId is null || !keptIds.Contains(menu.ParentId.Value))
            {
                roots.Add(menu);
                continue;
            }

            if (!childrenByParent.TryGetValue(menu.ParentId.Value, out var bucket))
            {
                bucket = [];
                childrenByParent[menu.ParentId.Value] = bucket;
            }

            bucket.Add(menu);
        }

        return [.. roots.Select(root => BuildNode(root, childrenByParent, pointsByMenu))];
    }

    private static MenuTreeNodeResponse BuildNode(
        Menu menu,
        IReadOnlyDictionary<int, List<Menu>> childrenByParent,
        IReadOnlyDictionary<int, IReadOnlyList<Permission>> pointsByMenu) =>
        new()
        {
            Id = menu.Id,
            Code = menu.Code,
            ParentId = menu.ParentId,
            Name = menu.ParseName(),
            Path = menu.Path,
            Icon = menu.Icon,
            SortOrder = menu.SortOrder,
            Audience = [.. menu.ParseAudience().Order(StringComparer.Ordinal)],
            Status = menu.Status,
            Permissions = pointsByMenu.TryGetValue(menu.Id, out var points)
                ?
                [
                    .. points.Select(point => new MenuPermissionResponse
                    {
                        Id = point.Id,
                        Code = point.Code,
                        Name = point.Name,
                        Status = point.Status,
                    }),
                ]
                : [],
            Children = childrenByParent.TryGetValue(menu.Id, out var children)
                ? [.. children.Select(child => BuildNode(child, childrenByParent, pointsByMenu))]
                : [],
        };

    private static MenuResponse ToResponse(Menu menu) => new()
    {
        Id = menu.Id,
        Code = menu.Code,
        ParentId = menu.ParentId,
        Name = menu.ParseName(),
        Path = menu.Path,
        Icon = menu.Icon,
        SortOrder = menu.SortOrder,
        Audience = [.. menu.ParseAudience().Order(StringComparer.Ordinal)],
        Status = menu.Status,
    };

    private static string? AuditStamp(IBackOfficeCaller caller) =>
        caller.UserId <= 0 ? null : $"{caller.UserId}:{caller.Nickname}";
}
