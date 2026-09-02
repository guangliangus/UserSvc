using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>EF Core adapter for the permission catalogue.</summary>
public sealed class PermissionRepository(UserSvcDbContext db) : IPermissionRepository
{
    public void Add(Permission permission) => db.Permissions.Add(permission);

    public async Task<IReadOnlyList<Permission>> ListAllAsync(CancellationToken cancellationToken) =>
        await Ordered(db.Permissions).ToListAsync(cancellationToken);

    public Task<Permission?> FindByIdAsync(int permissionId, CancellationToken cancellationToken) =>
        db.Permissions.FirstOrDefaultAsync(permission => permission.Id == permissionId, cancellationToken);

    public async Task<IReadOnlyList<Permission>> ListByRoleIdAsync(
        int roleId,
        CancellationToken cancellationToken) =>
        await Ordered(
                from permission in db.Permissions
                join grant in db.RolePermissions on permission.Id equals grant.PermissionId
                where grant.RoleId == roleId
                select permission)
            .ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<Permission>> ListByRoleIdsAsync(
        IReadOnlyCollection<int> roleIds,
        CancellationToken cancellationToken)
    {
        if (roleIds.Count == 0)
        {
            return [];
        }

        return await Ordered(
                (from permission in db.Permissions
                 join grant in db.RolePermissions on permission.Id equals grant.PermissionId
                 where roleIds.Contains(grant.RoleId) && permission.Status == PermissionStatuses.Active
                 select permission).Distinct())
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Permission>> ListByMenuIdsAsync(
        IReadOnlyCollection<int> menuIds,
        CancellationToken cancellationToken)
    {
        if (menuIds.Count == 0)
        {
            return [];
        }

        return await Ordered(db.Permissions
                .Where(permission => permission.MenuId != null && menuIds.Contains(permission.MenuId.Value)))
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Permission>> ListByCodesAsync(
        IReadOnlyCollection<string> codes,
        CancellationToken cancellationToken)
    {
        if (codes.Count == 0)
        {
            return [];
        }

        return await Ordered(db.Permissions.Where(permission => codes.Contains(permission.Code)))
            .ToListAsync(cancellationToken);
    }

    public Task<int> CountByCodesAsync(IReadOnlyCollection<string> codes, CancellationToken cancellationToken) =>
        codes.Count == 0
            ? Task.FromResult(0)
            : db.Permissions.CountAsync(permission => codes.Contains(permission.Code), cancellationToken);

    public Task DeleteByMenuIdAsync(int menuId, CancellationToken cancellationToken) =>
        db.Permissions.Where(permission => permission.MenuId == menuId)
            .ExecuteDeleteAsync(cancellationToken);

    /// <summary>Module then code, everywhere. The catalogue page and every grant read show the same
    /// order, so a point does not move depending on which screen is looking at it.</summary>
    private static IQueryable<Permission> Ordered(IQueryable<Permission> query) =>
        query.OrderBy(permission => permission.Module).ThenBy(permission => permission.Code);
}
