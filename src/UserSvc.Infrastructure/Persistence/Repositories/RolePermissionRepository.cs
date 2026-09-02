using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>EF Core adapter for a role's permission grants.</summary>
public sealed class RolePermissionRepository(UserSvcDbContext db, IClock clock) : IRolePermissionRepository
{
    public async Task<IReadOnlyList<Permission>> ListPermissionsByRoleIdsAsync(
        IReadOnlyCollection<int> roleIds,
        CancellationToken cancellationToken)
    {
        if (roleIds.Count == 0)
        {
            return [];
        }

        return await (from permission in db.Permissions
                      join grant in db.RolePermissions on permission.Id equals grant.PermissionId
                      where roleIds.Contains(grant.RoleId)
                      select permission)
            .Distinct()
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Delete then insert, addressed by code.
    /// <para>
    /// It joins the caller's transaction rather than opening one of its own. The Go original nested a
    /// transaction here and silently got a savepoint; EF's execution strategy refuses a nested
    /// transaction outright, so the nesting would have surfaced as a runtime failure on the first
    /// grant save.
    /// </para>
    /// <para>
    /// A code that resolves to nothing simply produces no row. Those were already refused upstream by
    /// the grant validator, and failing here would turn a validation answer into a 500.
    /// </para>
    /// </summary>
    public async Task ReplaceForRoleAsync(
        int roleId,
        IReadOnlyCollection<string> permissionCodes,
        string? createdBy,
        CancellationToken cancellationToken)
    {
        await db.RolePermissions.Where(grant => grant.RoleId == roleId).ExecuteDeleteAsync(cancellationToken);

        if (permissionCodes.Count == 0)
        {
            return;
        }

        var permissionIds = await db.Permissions
            .Where(permission => permissionCodes.Contains(permission.Code))
            .Select(permission => permission.Id)
            .ToListAsync(cancellationToken);

        var now = clock.UtcNow;
        db.RolePermissions.AddRange(permissionIds.Select(permissionId => new RolePermission
        {
            RoleId = roleId,
            PermissionId = permissionId,
            CreatedAt = now,
            CreatedBy = createdBy,
        }));
    }
}
