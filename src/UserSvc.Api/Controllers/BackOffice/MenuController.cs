using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Features.BackOffice.Rbac.Contracts;
using UserSvc.Application.Ports.Iam;

namespace UserSvc.Api.Controllers.BackOffice;

/// <summary>
/// The menu registry, and the caller's own sidebar.
/// <para>
/// Reading the management tree takes <c>uam.role.manage</c> or <c>uam.member.read</c> - the same pair
/// as a role's grants, because a grant payload is unreadable without the names of the menus it points
/// at. Writing takes <c>uam.menu.manage</c>, and the service re-asserts the platform super
/// administrator on top of it.
/// </para>
/// </summary>
[ApiController]
// The plane guard, not a permission one. Both are served by one OpenIddict instance, so a
// consumer access token satisfies a bare [Authorize] here - and its sub is an identity.users id
// that AdminScopeService then resolves against iam.backend_users, which numbers its rows
// independently. Measured on a running host before this line existed: a device-grant token for
// consumer 1 read the whole role and permission catalogue at 200 and created a role at 201,
// because back-office account 1 happens to be the platform super administrator. The actions below
// that carry no permission requirement are still open to every back-office user by design; what
// this asserts is only that the caller is on this plane at all.
[Authorize(Policy = BackOfficePolicies.BackOffice)]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/back-office")]
[Produces("application/json")]
public sealed class MenuController(MenuAppService menus, IBackOfficeCaller caller) : ControllerBase
{
    /// <summary>
    /// The management tree.
    /// </summary>
    /// <param name="audience">
    /// Accepted and echoed, but inert: audience filtering is switched off across all three of its
    /// sites. See <see cref="MenuAppService.GetMenuTreeAsync"/> for why, and for how to restore it.
    /// </param>
    /// <param name="status">ACTIVE or INACTIVE; omit for every status.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    [HttpGet("menus/tree")]
    [ProducesResponseType<MenuTreeResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public Task<MenuTreeResponse> GetMenuTree(
        [FromQuery] string? audience,
        [FromQuery] string? status,
        CancellationToken cancellationToken) =>
        menus.GetMenuTreeAsync(caller, audience, status, cancellationToken);

    /// <summary>
    /// The caller's own sidebar. <b>No route permission</b>: a brand-new member with no menus at all
    /// still has to be able to load the shell.
    /// </summary>
    [HttpGet("me/menus")]
    [ProducesResponseType<MenuTreeResponse>(StatusCodes.Status200OK)]
    public Task<MenuTreeResponse> GetMyMenus(CancellationToken cancellationToken) =>
        menus.GetGrantedMenuTreeAsync(caller.Authz.Menus, cancellationToken);

    /// <summary>Register a menu. Requires <c>uam.menu.manage</c>.</summary>
    [HttpPost("menus")]
    [ProducesResponseType<MenuResponse>(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<MenuResponse>> CreateMenu(
        [FromBody] CreateMenuRequest request,
        CancellationToken cancellationToken)
    {
        var created = await menus.CreateMenuAsync(caller, request, cancellationToken);
        return StatusCode(StatusCodes.Status201Created, created);
    }

    /// <summary>Edit a menu. Requires <c>uam.menu.manage</c>. Code and parent are immutable.</summary>
    [HttpPut("menus/{id:int}")]
    [ProducesResponseType<MenuResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public Task<MenuResponse> UpdateMenu(
        int id,
        [FromBody] UpdateMenuRequest request,
        CancellationToken cancellationToken) =>
        menus.UpdateMenuAsync(caller, id, request, cancellationToken);

    /// <summary>Remove a menu and the permission points on it. Requires <c>uam.menu.manage</c>.</summary>
    [HttpDelete("menus/{id:int}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> DeleteMenu(int id, CancellationToken cancellationToken)
    {
        await menus.DeleteMenuAsync(caller, id, cancellationToken);
        return NoContent();
    }
}
