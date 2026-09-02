using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>EF Core adapter for the role bindings of a membership.</summary>
public sealed class UserTenantRoleRepository(UserSvcDbContext db) : IUserTenantRoleRepository
{
    public async Task<IReadOnlyList<UserTenantRole>> ListByMemberIdAsync(
        int memberId, CancellationToken cancellationToken) =>
        await db.UserTenantRoles
            .Where(binding => binding.MemberId == memberId)
            .OrderBy(binding => binding.Id)
            .ToListAsync(cancellationToken);

    public async Task<IReadOnlyDictionary<int, IReadOnlyList<int>>> ListRoleIdsByMemberIdsAsync(
        IReadOnlyCollection<int> memberIds, CancellationToken cancellationToken)
    {
        if (memberIds.Count == 0)
        {
            return new Dictionary<int, IReadOnlyList<int>>();
        }

        var ids = memberIds.ToArray();

        var rows = await db.UserTenantRoles
            .Where(binding => ids.Contains(binding.MemberId))
            .OrderBy(binding => binding.Id)
            .Select(binding => new { binding.MemberId, binding.RoleId })
            .ToListAsync(cancellationToken);

        return rows
            .GroupBy(row => row.MemberId)
            .ToDictionary(
                group => group.Key,
                group => (IReadOnlyList<int>)[.. group.Select(row => row.RoleId)]);
    }

    /// <summary>
    /// Replaces a member's bindings wholesale.
    /// <para>
    /// The delete runs as a single statement rather than through the change tracker, so the caller
    /// pays for one round trip regardless of how many bindings there were. It must therefore run
    /// inside the caller's transaction - which it does, on the same connection - or a failure
    /// halfway through would leave the member with no roles at all.
    /// </para>
    /// </summary>
    public async Task ReplaceForMemberAsync(
        int memberId,
        IReadOnlyList<int> roleIds,
        string actor,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(roleIds);

        await db.UserTenantRoles
            .Where(binding => binding.MemberId == memberId)
            .ExecuteDeleteAsync(cancellationToken);

        if (roleIds.Count > 0)
        {
            db.UserTenantRoles.AddRange(roleIds.Distinct().Select(roleId => new UserTenantRole
            {
                MemberId = memberId,
                RoleId = roleId,
                CreatedAt = now,
                CreatedBy = actor,
            }));
        }

        await db.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Bindings that still count, joined to the membership they hang off.
    /// <para>
    /// The join is the whole point. A REMOVED or DISABLED member keeps its binding rows - the
    /// retirement is a status change, not a delete - so counting the binding table alone would
    /// answer "still in use" for a role nobody can exercise, and the delete guard above it would
    /// refuse forever.
    /// </para>
    /// </summary>
    public Task<int> CountActiveByRoleIdAsync(int roleId, CancellationToken cancellationToken) =>
        db.UserTenantRoles
            .Where(binding => binding.RoleId == roleId)
            .Join(
                db.TenantMembers.Where(member => member.Status == TenantMemberStatuses.Active),
                binding => binding.MemberId,
                member => member.Id,
                (binding, member) => binding.Id)
            .CountAsync(cancellationToken);

    /// <summary>
    /// The accounts a grant change on this role has to converge. Distinct, because one account can
    /// reach the same role through memberships of several tenants and its token version only needs
    /// bumping once.
    /// </summary>
    public async Task<IReadOnlyList<int>> ListUserIdsByRoleIdAsync(
        int roleId, CancellationToken cancellationToken) =>
        await db.UserTenantRoles
            .Where(binding => binding.RoleId == roleId)
            .Join(
                db.TenantMembers.Where(member => member.Status == TenantMemberStatuses.Active),
                binding => binding.MemberId,
                member => member.Id,
                (binding, member) => member.UserId)
            .Distinct()
            .OrderBy(userId => userId)
            .ToListAsync(cancellationToken);
}
