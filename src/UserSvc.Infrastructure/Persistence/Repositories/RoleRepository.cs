using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>EF Core adapter for the role catalogue.</summary>
public sealed class RoleRepository(UserSvcDbContext db) : IRoleRepository
{
    public void Add(Role role) => db.Roles.Add(role);

    public void Remove(Role role) => db.Roles.Remove(role);

    public async Task<IReadOnlyList<Role>> ListAllAsync(CancellationToken cancellationToken) =>
        await db.Roles.OrderBy(role => role.Id).ToListAsync(cancellationToken);

    public Task<Role?> FindByIdAsync(int roleId, CancellationToken cancellationToken) =>
        db.Roles.FirstOrDefaultAsync(role => role.Id == roleId, cancellationToken);

    public async Task<IReadOnlyList<Role>> FindByIdsAsync(
        IReadOnlyCollection<int> roleIds,
        CancellationToken cancellationToken)
    {
        if (roleIds.Count == 0)
        {
            return [];
        }

        return await db.Roles
            .Where(role => roleIds.Contains(role.Id))
            .OrderBy(role => role.Id)
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Role>> FindByCodesAsync(
        IReadOnlyCollection<string> codes,
        CancellationToken cancellationToken)
    {
        if (codes.Count == 0)
        {
            return [];
        }

        return await db.Roles
            .Where(role => codes.Contains(role.Code))
            .OrderBy(role => role.Id)
            .ToListAsync(cancellationToken);
    }

    public Task<bool> ExistsByCodeAsync(string code, CancellationToken cancellationToken) =>
        db.Roles.AnyAsync(role => role.Code == code, cancellationToken);

    /// <summary>
    /// Case- and whitespace-insensitive, over the whole catalogue.
    /// <para>
    /// <c>Trim()</c> and <c>ToLower()</c> translate to <c>btrim</c> and <c>lower</c>, giving
    /// <c>lower(btrim(name)) = lower(btrim(@name))</c>. Deliberately <b>not</b> <c>ILIKE</c>: that
    /// would read <c>%</c> and <c>_</c> inside a submitted name as wildcards, so a role called
    /// <c>ops_lead</c> would report a collision with <c>opsXlead</c>.
    /// </para>
    /// </summary>
    public Task<bool> ExistsByNameAsync(string name, int excludeRoleId, CancellationToken cancellationToken)
    {
#pragma warning disable CA1862 // The comparison has to run in the database, so it needs lower().
        var query = db.Roles.Where(role => role.Name.Trim().ToLower() == name.Trim().ToLower());
#pragma warning restore CA1862

        if (excludeRoleId > 0)
        {
            query = query.Where(role => role.Id != excludeRoleId);
        }

        return query.AnyAsync(cancellationToken);
    }

    /// <summary>A platform role matches on a NULL owner code, not on an empty one - the difference
    /// is the whole point of the column being nullable.</summary>
    public async Task<IReadOnlyList<Role>> ListByOwnerAsync(
        string ownerType,
        string? ownerCode,
        CancellationToken cancellationToken)
    {
        var query = db.Roles.Where(role => role.OwnerType == ownerType);

        query = ownerType == RoleOwnerTypes.System
            ? query.Where(role => role.OwnerCode == null)
            : query.Where(role => role.OwnerCode == ownerCode);

        return await query.OrderBy(role => role.Id).ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Role>> ListChildrenAsync(
        IReadOnlyCollection<int> parentRoleIds,
        CancellationToken cancellationToken)
    {
        if (parentRoleIds.Count == 0)
        {
            return [];
        }

        return await db.Roles
            .Where(role => role.ParentRoleId != null && parentRoleIds.Contains(role.ParentRoleId.Value))
            .OrderBy(role => role.Id)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// A recursive CTE, because the tree is three levels deep today and the ceiling has to cover all
    /// of it. The depth cap is what stops a corrupted parent chain from spinning the query forever;
    /// it is a safety valve, not a business limit.
    /// <para>
    /// Raw SQL through EF's own <c>FromSql</c>, so it runs on the same connection and inside the same
    /// transaction as everything around it (decision 15).
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<Role>> ListDescendantsAsync(
        IReadOnlyCollection<int> rootRoleIds,
        CancellationToken cancellationToken)
    {
        if (rootRoleIds.Count == 0)
        {
            return [];
        }

        var roots = rootRoleIds.ToArray();

        return await db.Roles.FromSql(
                $"""
                 WITH RECURSIVE subtree AS (
                     SELECT id, 1 AS depth
                     FROM iam.roles
                     WHERE parent_role_id = ANY({roots})
                     UNION ALL
                     SELECT child.id, parent.depth + 1
                     FROM iam.roles child
                     JOIN subtree parent ON child.parent_role_id = parent.id
                     WHERE parent.depth < {IamConstants.MaxRoleSubtreeDepth}
                 )
                 SELECT r.*
                 FROM iam.roles r
                 WHERE r.id IN (SELECT id FROM subtree)
                 """)
            .OrderBy(role => role.Id)
            .ToListAsync(cancellationToken);
    }

    public Task<int> CountChildrenAsync(int roleId, CancellationToken cancellationToken) =>
        db.Roles.CountAsync(role => role.ParentRoleId == roleId, cancellationToken);
}
