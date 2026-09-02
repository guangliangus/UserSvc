using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Features.BackOffice.Rbac.Contracts;
using UserSvc.Application.Ports.Iam;

namespace UserSvc.Api.Controllers.BackOffice;

/// <summary>
/// Role and permission administration for the back office.
/// <para>
/// The permission point each route expects is named on the action. Note that <c>GET /roles</c>
/// deliberately has none: every authenticated back-office user may call it, because a tenant
/// administrator needs it as the candidate list for assigning roles. Its confidentiality is the
/// service's visibility narrowing, not a route gate.
/// </para>
/// </summary>
[ApiController]
[Authorize]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/back-office")]
[Produces("application/json")]
public sealed class RbacController(
    RoleAppService roles,
    RoleGrantsAppService grants,
    PermissionCatalogAppService permissions,
    SuperAdminAppService superAdmin,
    IBackOfficeCaller caller) : ControllerBase
{
    /// <summary>Create a role. Requires <c>uam.role.manage</c>.</summary>
    [HttpPost("roles")]
    [ProducesResponseType<RoleResponse>(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<RoleResponse>> CreateRole(
        [FromBody] CreateRoleRequest request,
        CancellationToken cancellationToken)
    {
        var created = await roles.CreateRoleAsync(caller, request, cancellationToken);
        return StatusCode(StatusCodes.Status201Created, created);
    }

    /// <summary>
    /// The role catalogue, narrowed to what this caller may see. <b>No route permission.</b>
    /// </summary>
    [HttpGet("roles")]
    [ProducesResponseType<IReadOnlyList<RoleResponse>>(StatusCodes.Status200OK)]
    public Task<IReadOnlyList<RoleResponse>> GetRoles(CancellationToken cancellationToken) =>
        roles.GetRolesAsync(caller, cancellationToken);

    /// <summary>
    /// Whether a role name is already taken. Requires <c>uam.role.manage</c>.
    /// <para>
    /// Registered before the parameterised role routes, and gated like a write rather than like a
    /// read: it answers across every tenant's roles.
    /// </para>
    /// </summary>
    [HttpGet("roles/name-exists")]
    [ProducesResponseType<RoleNameExistsResponse>(StatusCodes.Status200OK)]
    public Task<RoleNameExistsResponse> RoleNameExists(
        [FromQuery] string? name,
        [FromQuery(Name = "exclude_role_id")] int excludeRoleId,
        CancellationToken cancellationToken) =>
        roles.RoleNameExistsAsync(caller, name ?? string.Empty, excludeRoleId, cancellationToken);

    /// <summary>Edit a role. Requires <c>uam.role.manage</c>.</summary>
    [HttpPut("roles/{id:int}")]
    [ProducesResponseType<RoleResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public Task<RoleResponse> UpdateRole(
        int id,
        [FromBody] UpdateRoleRequest request,
        CancellationToken cancellationToken) =>
        roles.UpdateRoleAsync(caller, id, request, cancellationToken);

    /// <summary>Delete a role. Requires <c>uam.role.manage</c>.</summary>
    [HttpDelete("roles/{id:int}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> DeleteRole(int id, CancellationToken cancellationToken)
    {
        await roles.DeleteRoleAsync(caller, id, cancellationToken);
        return NoContent();
    }

    /// <summary>
    /// What a role grants. Requires <c>uam.role.manage</c> <b>or</b> <c>uam.member.read</c>: whoever
    /// can see who holds a role must be able to see what it confers, or the member page can only show
    /// opaque role names.
    /// </summary>
    [HttpGet("roles/{id:int}/grants")]
    [ProducesResponseType<RoleGrantsResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public Task<RoleGrantsResponse> GetRoleGrants(int id, CancellationToken cancellationToken) =>
        grants.GetRoleGrantsAsync(caller, id, cancellationToken);

    /// <summary>Replace a role's grants. Requires <c>uam.role.manage</c>.</summary>
    [HttpPut("roles/{id:int}/grants")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> SaveRoleGrants(
        int id,
        [FromBody] SaveRoleGrantsRequest request,
        CancellationToken cancellationToken)
    {
        await grants.SaveRoleGrantsAsync(caller, id, request, cancellationToken);
        return NoContent();
    }

    /// <summary>A role's effective permission points. Requires <c>uam.role.manage</c> or
    /// <c>uam.member.read</c>.</summary>
    [HttpGet("roles/{id:int}/permissions")]
    [ProducesResponseType<IReadOnlyList<PermissionResponse>>(StatusCodes.Status200OK)]
    public Task<IReadOnlyList<PermissionResponse>> GetRolePermissions(
        int id,
        CancellationToken cancellationToken) =>
        permissions.GetPermissionsByRoleAsync(caller, id, cancellationToken);

    /// <summary>
    /// The legacy permissions-only editor. Requires <c>uam.role.manage</c>. It derives the owning
    /// menu closure and goes through the full grant path, so it enforces exactly the same rules.
    /// </summary>
    [HttpPut("roles/{id:int}/permissions")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> UpdateRolePermissions(
        int id,
        [FromBody] UpdateRolePermissionsRequest request,
        CancellationToken cancellationToken)
    {
        await grants.UpdateRolePermissionsAsync(caller, id, request, cancellationToken);
        return NoContent();
    }

    /// <summary>
    /// What the caller may do with roles. <b>No route permission</b> - somebody has to be able to ask
    /// "can I create a role?" before they know the answer.
    /// </summary>
    [HttpGet("me/role-scope")]
    [ProducesResponseType<MyRoleScopeResponse>(StatusCodes.Status200OK)]
    public Task<MyRoleScopeResponse> GetMyRoleScope(CancellationToken cancellationToken) =>
        roles.GetMyRoleScopeAsync(caller, cancellationToken);

    /// <summary>The permission catalogue. Requires <c>uam.role.manage</c> - tenant administrators
    /// need it to configure their roles. The service asserts that point itself.</summary>
    [HttpGet("permissions")]
    [ProducesResponseType<IReadOnlyList<PermissionResponse>>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public Task<IReadOnlyList<PermissionResponse>> GetPermissions(CancellationToken cancellationToken) =>
        permissions.GetPermissionsAsync(caller, cancellationToken);

    /// <summary>Add a permission point. Requires <c>uam.permission.manage</c>, and the service
    /// re-asserts the platform super administrator.</summary>
    [HttpPost("permissions")]
    [ProducesResponseType<PermissionResponse>(StatusCodes.Status201Created)]
    public async Task<ActionResult<PermissionResponse>> CreatePermission(
        [FromBody] CreatePermissionRequest request,
        CancellationToken cancellationToken)
    {
        var created = await permissions.CreatePermissionAsync(caller, request, cancellationToken);
        return StatusCode(StatusCodes.Status201Created, created);
    }

    /// <summary>Edit a permission point. Requires <c>uam.permission.manage</c>.</summary>
    [HttpPut("permissions/{id:int}")]
    [ProducesResponseType<PermissionResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public Task<PermissionResponse> UpdatePermission(
        int id,
        [FromBody] UpdatePermissionRequest request,
        CancellationToken cancellationToken) =>
        permissions.UpdatePermissionAsync(caller, id, request, cancellationToken);

    /// <summary>What one account effectively holds. Requires <c>uam.member.read</c>.</summary>
    [HttpGet("users/{id:int}/permissions")]
    [ProducesResponseType<IReadOnlyList<PermissionResponse>>(StatusCodes.Status200OK)]
    public Task<IReadOnlyList<PermissionResponse>> GetUserPermissions(
        int id,
        CancellationToken cancellationToken) =>
        permissions.GetPermissionsByUserAsync(caller, id, cancellationToken);

    /// <summary>
    /// Set an account's whole-dimension data access. Requires <c>uam.company.manage</c>, and the
    /// service additionally requires the caller to be the platform super administrator.
    /// </summary>
    [HttpPut("users/{id:int}/global-access")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> SetGlobalAccess(
        int id,
        [FromBody] SetGlobalAccessRequest request,
        CancellationToken cancellationToken)
    {
        await superAdmin.SetUserGlobalAccessAsync(caller, id, request, cancellationToken);
        return NoContent();
    }

    /// <summary>
    /// Grant or revoke the platform super-administrator flag. Requires <c>uam.company.manage</c> plus
    /// platform super-administrator standing; revoking the last active one is refused by an atomic
    /// guard rather than by a read-then-write.
    /// </summary>
    [HttpPut("users/{id:int}/super-admin")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> SetSuperAdmin(
        int id,
        [FromBody] SetSuperAdminRequest request,
        CancellationToken cancellationToken)
    {
        await superAdmin.SetSuperAdminAsync(caller, id, request, cancellationToken);
        return NoContent();
    }
}
