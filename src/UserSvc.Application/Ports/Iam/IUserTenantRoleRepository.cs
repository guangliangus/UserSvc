namespace UserSvc.Application.Ports.Iam;

/// <summary>
/// Role bindings hanging off a tenant membership (spec 2.6). The table belongs to the tenant slice;
/// the contract lives here because the whole of it is consumed by role management, and the tenant
/// slice uses only the first three methods.
/// <para>
/// It deals in ids rather than in the tenant slice's entity on purpose: this port is the seam
/// between two bounded contexts, and the row shape on the other side is not this module's business.
/// </para>
/// </summary>
public interface IUserTenantRoleRepository
{
    Task<IReadOnlyList<UserTenantRoleBinding>> ListByMemberIdAsync(
        int memberId,
        CancellationToken cancellationToken);

    /// <summary>Role ids per membership. A membership with no bindings is <b>absent</b> from the
    /// map rather than present with an empty list; empty input gives an empty map, never null.</summary>
    Task<IReadOnlyDictionary<int, IReadOnlyList<int>>> ListRoleIdsByMemberIdsAsync(
        IReadOnlyCollection<int> memberIds,
        CancellationToken cancellationToken);

    /// <summary>Delete-then-insert of one membership's whole role set. Must run inside the caller's
    /// transaction.</summary>
    Task ReplaceForMemberAsync(
        int memberId,
        IReadOnlyCollection<int> roleIds,
        string? createdBy,
        CancellationToken cancellationToken);

    /// <summary>
    /// How many <b>active</b> memberships still bind this role. Rows left behind by removed or
    /// disabled members do not count: the foreign key cascades anyway, so this is a usability check,
    /// and counting them would jam a role nobody uses behind a permanent "still in use".
    /// </summary>
    Task<int> CountActiveByRoleIdAsync(int roleId, CancellationToken cancellationToken);

    /// <summary>Distinct users reachable through an active membership bound to this role - the set
    /// whose sessions have to converge after a grant change.</summary>
    Task<IReadOnlyList<int>> ListUserIdsByRoleIdAsync(int roleId, CancellationToken cancellationToken);
}

/// <summary>One binding row: a membership and the role it carries.</summary>
public sealed record UserTenantRoleBinding(int Id, int MemberId, int RoleId);
