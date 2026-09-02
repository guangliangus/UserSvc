using UserSvc.Domain.Iam;

namespace UserSvc.Application.Ports.Iam;

/// <summary>The permission catalogue's persistence outlet (spec 2.2).</summary>
public interface IPermissionRepository
{
    void Add(Permission permission);

    /// <summary>Every point in every status, ordered by module then code. The catalogue page has to
    /// show INACTIVE rows - that is the only way one gets reactivated.</summary>
    Task<IReadOnlyList<Permission>> ListAllAsync(CancellationToken cancellationToken);

    Task<Permission?> FindByIdAsync(int permissionId, CancellationToken cancellationToken);

    /// <summary><b>Unfiltered by status</b> on purpose - the caller decides whether it is reading a
    /// catalogue (all statuses) or an effective grant (ACTIVE only).</summary>
    Task<IReadOnlyList<Permission>> ListByRoleIdAsync(int roleId, CancellationToken cancellationToken);

    /// <summary>
    /// Distinct ACTIVE points across several roles.
    /// <para>
    /// This one <b>does</b> filter to ACTIVE, because its callers are answering "what does this
    /// account effectively hold": an INACTIVE point grants nothing, so counting it would report a
    /// number larger than the account can actually use.
    /// </para>
    /// </summary>
    Task<IReadOnlyList<Permission>> ListByRoleIdsAsync(
        IReadOnlyCollection<int> roleIds,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<Permission>> ListByMenuIdsAsync(
        IReadOnlyCollection<int> menuIds,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<Permission>> ListByCodesAsync(
        IReadOnlyCollection<string> codes,
        CancellationToken cancellationToken);

    Task<int> CountByCodesAsync(IReadOnlyCollection<string> codes, CancellationToken cancellationToken);

    /// <summary>
    /// Hard delete of every point on a menu. Must run in the <b>same transaction</b> as, and before,
    /// the menu delete: <c>permissions.menu_id</c> is ON DELETE RESTRICT, so the other order simply
    /// fails. The grant rows pointing at them follow by cascade.
    /// </summary>
    Task DeleteByMenuIdAsync(int menuId, CancellationToken cancellationToken);
}
