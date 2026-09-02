using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac.Contracts;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>
/// The permission-point catalogue.
/// <para>
/// The catalogue is platform property: writing to it is re-asserted as a super-administrator check
/// inside the service, because the route's permission point is an ordinary one that could be hung on
/// any role. Reading it stays open to role administrators - they need it to configure a role.
/// </para>
/// </summary>
public sealed class PermissionCatalogAppService(
    IPermissionRepository permissions,
    IRoleRepository roles,
    AdminScopeService adminScopes,
    RoleVisibilityService roleVisibility,
    UserVisibilityService userVisibility,
    IUnitOfWork unitOfWork,
    IClock clock)
{
    /// <summary>
    /// The whole catalogue, every status. <b>Not filtered</b>: this is the catalogue, not anybody's
    /// grant, and an INACTIVE point has to be visible to be reactivated.
    /// <para>
    /// Gated on <c>uam.role.manage</c>, which is the point the route is documented to carry. It is
    /// asserted here as well because the catalogue names every point the platform can enforce, and
    /// handing that list to any authenticated account is a map of the system's own controls.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<PermissionResponse>> GetPermissionsAsync(
        IBackOfficeCaller caller,
        CancellationToken cancellationToken)
    {
        await adminScopes.AssertHoldsAnyAsync(
            caller, [IamConstants.PermissionCodeRoleManage], cancellationToken);

        return [.. (await permissions.ListAllAsync(cancellationToken)).Select(ToResponse)];
    }

    /// <summary>Add a point. Its status is fixed to ACTIVE - there is no reason to create a
    /// soft-deleted one.</summary>
    public async Task<PermissionResponse> CreatePermissionAsync(
        IBackOfficeCaller caller,
        CreatePermissionRequest request,
        CancellationToken cancellationToken)
    {
        await adminScopes.AssertPlatformSuperAdminAsync(caller, cancellationToken);

        var now = clock.UtcNow;
        var permission = new Permission
        {
            Code = request.Code,
            Name = request.Name,
            Description = request.Description,
            Module = request.Module,
            Status = PermissionStatuses.Active,
            MenuId = request.MenuId,
            CreatedAt = now,
            UpdatedAt = now,
        };

        permissions.Add(permission);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return ToResponse(permission);
    }

    /// <summary>Edit a point. Its code is not editable: it is the handle every grant refers to.</summary>
    public async Task<PermissionResponse> UpdatePermissionAsync(
        IBackOfficeCaller caller,
        int permissionId,
        UpdatePermissionRequest request,
        CancellationToken cancellationToken)
    {
        await adminScopes.AssertPlatformSuperAdminAsync(caller, cancellationToken);

        if (!PermissionStatuses.IsValid(request.Status))
        {
            throw new BadRequestException(ErrorCodes.BadRequest, $"Invalid status: {request.Status}.");
        }

        var permission = await permissions.FindByIdAsync(permissionId, cancellationToken)
                         ?? throw new NotFoundException(ErrorCodes.NotFound, "Permission was not found.");

        permission.Name = request.Name;
        permission.Description = request.Description;
        permission.Module = request.Module;
        permission.Status = request.Status;
        // Full replacement: a null menu id detaches the point and makes it service-level.
        permission.MenuId = request.MenuId;
        permission.UpdatedAt = clock.UtcNow;

        await unitOfWork.SaveChangesAsync(cancellationToken);
        return ToResponse(permission);
    }

    /// <summary>
    /// What one role effectively grants.
    /// <para>
    /// No administrator gate here - the route's own permission pair is the whole authorisation, and
    /// the ownership check is what keeps a caller out of another tenant's role. That is deliberate:
    /// whoever can read <i>who</i> holds a role has to be able to read <i>what</i> it grants, or the
    /// member page can only show opaque role names.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<PermissionResponse>> GetPermissionsByRoleAsync(
        IBackOfficeCaller caller,
        int roleId,
        CancellationToken cancellationToken)
    {
        var role = await roles.FindByIdAsync(roleId, cancellationToken)
                   ?? throw new NotFoundException(ErrorCodes.NotFound, "Role was not found.");

        await roleVisibility.AssertRoleVisibleAsync(caller, role, mutate: false, cancellationToken);

        var granted = await permissions.ListByRoleIdAsync(roleId, cancellationToken);
        return ActiveOnly(granted);
    }

    /// <summary>
    /// What one account effectively holds.
    /// <para>
    /// Narrowed twice: once to decide whether the caller may open the account at all, and again per
    /// membership, because the account may also belong to tenants the caller does not administer and
    /// those bindings are not theirs to read.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<PermissionResponse>> GetPermissionsByUserAsync(
        IBackOfficeCaller caller,
        int userId,
        CancellationToken cancellationToken)
    {
        await userVisibility.AssertCanReadUserAsync(caller, userId, cancellationToken);
        var filter = await userVisibility.ResolveUserReadFilterAsync(caller, cancellationToken);

        // The target's own flag. A platform super administrator's access is hard-coded rather than
        // carried by grant rows, so adding their bindings up would report an empty set for the
        // strongest account in the system.
        if (await adminScopes.IsPlatformSuperAdminAsync(userId, cancellationToken))
        {
            return ActiveOnly(await permissions.ListAllAsync(cancellationToken));
        }

        var visibleRoles = await userVisibility.VisibleActiveUserRolesAsync(userId, filter, cancellationToken);
        if (visibleRoles.Count == 0)
        {
            return [];
        }

        var granted = await permissions.ListByRoleIdsAsync(
            [.. visibleRoles.Select(role => role.Id)], cancellationToken);

        return ActiveOnly(granted);
    }

    /// <summary>
    /// Effective grants only.
    /// <para>
    /// An INACTIVE point grants nothing, so counting it in an "effective permissions" read shows more
    /// than the role actually confers. The management page still sees them - that read is of the
    /// catalogue, not of anybody's authority.
    /// </para>
    /// </summary>
    private static IReadOnlyList<PermissionResponse> ActiveOnly(IReadOnlyList<Permission> candidates) =>
        [.. candidates.Where(permission => permission.IsActive()).Select(ToResponse)];

    private static PermissionResponse ToResponse(Permission permission) => new()
    {
        Id = permission.Id,
        Code = permission.Code,
        Name = permission.Name,
        Description = permission.Description ?? string.Empty,
        Module = permission.Module,
        Status = permission.Status,
        MenuId = permission.MenuId,
    };
}
