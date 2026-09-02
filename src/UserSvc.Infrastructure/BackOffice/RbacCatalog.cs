using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// The tenant slice's read window onto the menu and permission catalogue, assembled from the four
/// RBAC repositories that already own those tables.
/// <para>
/// Nothing here computes: every method is one repository call plus a projection. The one judgement
/// it makes is which repository answers which question - menus and role grants come from their own
/// tables, and the "every active permission code" list is filtered here rather than in SQL because
/// the permission repository deliberately exposes the catalogue whole (the caller decides what an
/// inactive point means, and on this one path it means "not granted to anybody").
/// </para>
/// </summary>
public sealed class RbacCatalog(
    IMenuRepository menus,
    IPermissionRepository permissions,
    IRoleMenuRepository roleMenus,
    IRolePermissionRepository rolePermissions) : IRbacCatalog
{
    public async Task<IReadOnlyList<MenuRecord>> ListActiveMenusAsync(CancellationToken cancellationToken) =>
        [.. (await menus.ListActiveAsync(cancellationToken))
            .Select(menu => new MenuRecord(menu.Id, menu.Code, menu.ParentId, menu.ParseAudience()))];

    public Task<IReadOnlyList<int>> ListMenuIdsByRolesAsync(
        IReadOnlyCollection<int> roleIds, CancellationToken cancellationToken) =>
        roleMenus.ListMenuIdsByRoleIdsAsync(roleIds, cancellationToken);

    public async Task<IReadOnlyList<PermissionRecord>> ListPermissionsByRolesAsync(
        IReadOnlyCollection<int> roleIds, CancellationToken cancellationToken) =>
        [.. (await rolePermissions.ListPermissionsByRoleIdsAsync(roleIds, cancellationToken))
            .Select(Project)];

    /// <summary>
    /// Every ACTIVE permission code, ordered so that two calls answer identically. INACTIVE points
    /// are dropped here and not by the repository: this is the platform super administrator's whole
    /// surface, so a retired point that stayed in the list would be granted to the one account no
    /// other gate narrows.
    /// </summary>
    public async Task<IReadOnlyList<string>> ListActivePermissionCodesAsync(CancellationToken cancellationToken) =>
        [.. (await permissions.ListAllAsync(cancellationToken))
            .Where(permission => permission.IsActive())
            .Select(permission => permission.Code)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];

    private static PermissionRecord Project(Permission permission) =>
        new(permission.Id, permission.Code, permission.Status, permission.MenuId);
}
