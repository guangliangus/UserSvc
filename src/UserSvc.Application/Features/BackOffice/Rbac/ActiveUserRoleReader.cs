using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>
/// The one path from an account to the roles it actually holds: active membership, then binding,
/// then role. Nothing else grants a role - the legacy direct user-to-role tables were dropped, and a
/// role that cannot be reached from an ACTIVE membership grants nothing at all.
/// </summary>
public sealed class ActiveUserRoleReader(
    ITenantMemberDirectory members,
    IUserTenantRoleRepository bindings,
    IRoleRepository roles)
{
    /// <summary>
    /// Role ids held through active memberships, ascending.
    /// <para>
    /// An empty <c>dimension</c> keeps every membership. Naming one keeps only that side, which is
    /// what locks the role page to the dimension the caller signed in as: acting as a company must
    /// not surface a role held through a <i>supplier</i> membership, and the reverse.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<int>> ListRoleIdsAsync(
        int userId,
        string dimension,
        CancellationToken cancellationToken)
    {
        var memberships = await members.ListActiveByUserAsync(userId, cancellationToken);
        var memberIds = memberships
            .Where(m => dimension.Length == 0 || m.TenantType == dimension)
            .Select(m => m.Id)
            .ToList();

        if (memberIds.Count == 0)
        {
            return [];
        }

        var roleIdsByMember = await bindings.ListRoleIdsByMemberIdsAsync(memberIds, cancellationToken);
        return CallerFacts.DedupeSort(roleIdsByMember.Values.SelectMany(ids => ids));
    }

    /// <summary>The same set, resolved to rows.</summary>
    public async Task<IReadOnlyList<Role>> ListRolesAsync(
        int userId,
        string dimension,
        CancellationToken cancellationToken)
    {
        var roleIds = await ListRoleIdsAsync(userId, dimension, cancellationToken);
        return roleIds.Count == 0 ? [] : await roles.FindByIdsAsync(roleIds, cancellationToken);
    }
}
