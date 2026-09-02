using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Ports.Iam;

/// <summary>
/// Role bindings hanging off a tenant membership (spec 2.6). The table's DDL belongs to the tenant
/// slice; the contract lives here because the whole of it is consumed by role management, and the
/// tenant slice uses only the first three methods.
/// <para>
/// It deals in <see cref="UserTenantRole"/> - the row as the database holds it - rather than in a
/// projection of its own. An earlier draft of this port declared a separate binding record so that
/// role management would not have to name the tenant slice's entity, which cost a mapping layer and
/// a second name for one table and bought nothing: both slices reference the same domain assembly,
/// and every other repository port here hands back its own entity.
/// </para>
/// </summary>
public interface IUserTenantRoleRepository
{
    /// <summary>One membership's bindings, ordered by id.</summary>
    Task<IReadOnlyList<UserTenantRole>> ListByMemberIdAsync(
        int memberId,
        CancellationToken cancellationToken);

    /// <summary>Role ids per membership. A membership with no bindings is <b>absent</b> from the
    /// map rather than present with an empty list; empty input gives an empty map, never null.</summary>
    Task<IReadOnlyDictionary<int, IReadOnlyList<int>>> ListRoleIdsByMemberIdsAsync(
        IReadOnlyCollection<int> memberIds,
        CancellationToken cancellationToken);

    /// <summary>
    /// Delete-then-insert of one membership's whole role set. Must run inside the caller's
    /// transaction.
    /// <para>
    /// The caller is responsible for having merged in the bindings it is not allowed to touch -
    /// this method takes the final set at face value. <paramref name="now"/> is passed rather than
    /// read from a clock here so that one write stamps every row it inserts identically.
    /// </para>
    /// </summary>
    Task ReplaceForMemberAsync(
        int memberId,
        IReadOnlyList<int> roleIds,
        string actor,
        DateTimeOffset now,
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
