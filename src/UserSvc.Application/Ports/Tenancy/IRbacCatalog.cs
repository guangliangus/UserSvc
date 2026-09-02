namespace UserSvc.Application.Ports.Tenancy;

/// <summary>
/// A menu node, as the context funnel needs it.
/// <para>
/// <c>ParentId</c> is null at the top level; menus are resolved together with their ancestors,
/// because a granted child that renders without its parent group is not a menu, it is an orphan.
/// <c>Audience</c> lists which tenant kinds the menu is meant for - <c>platform</c>,
/// <c>company</c>, <c>supplier</c> - and is stored as a JSON array. See <c>TenantMenuResolver</c>
/// for why the filter that reads it is currently switched off.
/// </para>
/// </summary>
public sealed record MenuRecord(int Id, string Code, int? ParentId, IReadOnlyList<string> Audience);

/// <summary>
/// A permission point.
/// <para>
/// <c>MenuId</c> is the menu this permission hangs off, or null for a service-level point with no
/// page behind it. Null-menu points may only be granted through a SYSTEM role - a tenant's own
/// custom role must never be able to carry one.
/// </para>
/// </summary>
public sealed record PermissionRecord(int Id, string Code, string Status, int? MenuId);

/// <summary>Read side of the menu and permission catalogue.</summary>
public interface IRbacCatalog
{
    /// <summary>Every ACTIVE menu. Menus that are inactive or gone are what turns a granted menu
    /// id into nothing, and their permission points fall with them.</summary>
    Task<IReadOnlyList<MenuRecord>> ListActiveMenusAsync(CancellationToken cancellationToken);

    /// <summary>Menu ids granted by the given roles.</summary>
    Task<IReadOnlyList<int>> ListMenuIdsByRolesAsync(
        IReadOnlyCollection<int> roleIds, CancellationToken cancellationToken);

    /// <summary>Permission points carried by the given roles, in whatever status they are in -
    /// the caller filters, because it also has to decide what an inactive one means.</summary>
    Task<IReadOnlyList<PermissionRecord>> ListPermissionsByRolesAsync(
        IReadOnlyCollection<int> roleIds, CancellationToken cancellationToken);

    /// <summary>Every ACTIVE permission code. The platform super administrator's surface, and only
    /// theirs - reaching for this on any other path is how a full-access short circuit gets built
    /// by accident.</summary>
    Task<IReadOnlyList<string>> ListActivePermissionCodesAsync(CancellationToken cancellationToken);
}
