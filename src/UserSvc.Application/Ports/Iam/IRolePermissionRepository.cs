using UserSvc.Domain.Iam;

namespace UserSvc.Application.Ports.Iam;

/// <summary>Permission grants of a role (spec 2.5).</summary>
public interface IRolePermissionRepository
{
    /// <summary>Distinct permission rows granted to any of these roles. <b>Unordered and
    /// unfiltered by status</b> - the service layer decides what "effective" means for its
    /// question.</summary>
    Task<IReadOnlyList<Permission>> ListPermissionsByRoleIdsAsync(
        IReadOnlyCollection<int> roleIds,
        CancellationToken cancellationToken);

    /// <summary>
    /// Delete-then-insert of one role's whole permission set, addressed by code. Unknown codes
    /// silently produce no row - they were already rejected upstream by the grant validator, and
    /// failing here would turn a validation answer into a 500.
    /// <para>
    /// Joins the caller's transaction rather than opening its own: the Go original nested a
    /// transaction here and got a savepoint, whereas an EF execution strategy refuses a nested one
    /// outright.
    /// </para>
    /// </summary>
    Task ReplaceForRoleAsync(
        int roleId,
        IReadOnlyCollection<string> permissionCodes,
        string? createdBy,
        CancellationToken cancellationToken);
}
