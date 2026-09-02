namespace UserSvc.Application.Ports.Iam;

/// <summary>Menu grants of a role (spec 2.4).</summary>
public interface IRoleMenuRepository
{
    /// <summary>Distinct menu ids granted to any of these roles, ascending. Empty input gives an
    /// empty list, never null.</summary>
    Task<IReadOnlyList<int>> ListMenuIdsByRoleIdsAsync(
        IReadOnlyCollection<int> roleIds,
        CancellationToken cancellationToken);

    /// <summary>
    /// Delete-then-insert of one role's whole menu set. <b>Must run inside the caller's
    /// transaction</b>, together with the permission replacement: half-applied grants are a role
    /// that grants a menu without the points on it, or the reverse.
    /// </summary>
    Task ReplaceForRoleAsync(
        int roleId,
        IReadOnlyCollection<int> menuIds,
        string? createdBy,
        CancellationToken cancellationToken);
}
