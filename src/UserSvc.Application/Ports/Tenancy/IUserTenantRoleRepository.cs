using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Ports.Tenancy;

/// <summary>Persistence outlet for the role bindings of a membership. Keyed by member id, never
/// by user id - see <see cref="UserTenantRole"/>.</summary>
public interface IUserTenantRoleRepository
{
    Task<IReadOnlyList<UserTenantRole>> ListByMemberAsync(int memberId, CancellationToken cancellationToken);

    /// <summary>Role ids for several memberships at once. Members with no bindings are absent.</summary>
    Task<IReadOnlyDictionary<int, IReadOnlyList<int>>> ListRoleIdsByMembersAsync(
        IReadOnlyCollection<int> memberIds, CancellationToken cancellationToken);

    /// <summary>
    /// Replaces a member's bindings wholesale, inside the caller's transaction. The caller is
    /// responsible for having merged in the bindings it is not allowed to touch - this method
    /// takes the final set at face value.
    /// </summary>
    Task ReplaceForMemberAsync(
        int memberId,
        IReadOnlyList<int> roleIds,
        string actor,
        DateTimeOffset now,
        CancellationToken cancellationToken);
}
