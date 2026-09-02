using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>EF Core adapter for a role's menu grants.</summary>
public sealed class RoleMenuRepository(UserSvcDbContext db, IClock clock) : IRoleMenuRepository
{
    public async Task<IReadOnlyList<int>> ListMenuIdsByRoleIdsAsync(
        IReadOnlyCollection<int> roleIds,
        CancellationToken cancellationToken)
    {
        if (roleIds.Count == 0)
        {
            return [];
        }

        return await db.RoleMenus
            .Where(grant => roleIds.Contains(grant.RoleId))
            .Select(grant => grant.MenuId)
            .Distinct()
            .OrderBy(menuId => menuId)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Delete then insert. It stays inside whatever transaction the caller opened - the permission
    /// replacement runs in the same one, and a role granted menus but not the points on them (or the
    /// reverse) is a broken configuration nobody asked for.
    /// </summary>
    public async Task ReplaceForRoleAsync(
        int roleId,
        IReadOnlyCollection<int> menuIds,
        string? createdBy,
        CancellationToken cancellationToken)
    {
        await db.RoleMenus.Where(grant => grant.RoleId == roleId).ExecuteDeleteAsync(cancellationToken);

        if (menuIds.Count == 0)
        {
            return;
        }

        var now = clock.UtcNow;
        db.RoleMenus.AddRange(menuIds.Select(menuId => new RoleMenu
        {
            RoleId = roleId,
            MenuId = menuId,
            CreatedAt = now,
            CreatedBy = createdBy,
        }));
    }
}
