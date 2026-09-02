using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Ports.Tenancy;

namespace UserSvc.Api.Controllers.BackOffice;

/// <summary>
/// Managing the members of one tenant.
/// <para>
/// The tenant is in the path rather than taken from the caller's own context on purpose: a global
/// operator legitimately manages tenants they are not acting in, and the service checks the path
/// tenant against the caller's context on every action. What the path must never contain is the
/// whole-dimension sentinel - the service refuses it, and the reason it has to is written up there.
/// </para>
/// <para>
/// Every action is gated twice, and the two gates answer different questions.
/// <see cref="BackOfficePermissions"/> answers "was this caller granted this permission code",
/// which is what the Go service's <c>RequirePermission</c> route middleware did; the application
/// service then answers "does this caller's context reach this tenant" and, for the writes, "are
/// they an administrator of it", re-reading standing from the database rather than from the token.
/// The permission gate is not redundant with the second: reading the roster of the tenant you are
/// acting in deliberately does <b>not</b> require administrator standing, so without it any member
/// of a tenant could read its full roster including decrypted e-mail addresses.
/// </para>
/// </summary>
[ApiController]
[Authorize(Policy = BackOfficePolicies.BackOffice)]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/back-office/tenants/{tenantType}/{tenantCode}/members")]
[Produces("application/json")]
public sealed class TenantMemberController(
    TenantMemberAppService memberService, IAuthzSnapshotProvider snapshots) : ControllerBase
{
    /// <summary>Requires the <c>uam.member.read</c> permission.</summary>
    public const string ReadPermission = "uam.member.read";

    /// <summary>Requires the <c>uam.member.manage</c> permission.</summary>
    public const string ManagePermission = "uam.member.manage";

    /// <summary>
    /// One page of the tenant's roster. Requires <see cref="ReadPermission"/>.
    /// <para>
    /// <c>status</c> takes ACTIVE, DISABLED or REMOVED; omitted means everything except removed.
    /// <c>keyword</c> matches an e-mail address exactly - the stored address is encrypted, so
    /// there is nothing to match a substring against - and anything else against the name fields.
    /// </para>
    /// </summary>
    [HttpGet]
    [ProducesResponseType<TenantMemberListResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<TenantMemberListResponse> List(
        string tenantType,
        string tenantCode,
        CancellationToken cancellationToken,
        [FromQuery] string? status = null,
        [FromQuery] string? keyword = null,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20)
    {
        var caller = await RequireAsync(ReadPermission, cancellationToken);

        return await memberService.ListMembersAsync(
            caller,
            tenantType,
            tenantCode,
            status,
            keyword,
            page,
            pageSize,
            cancellationToken);
    }

    /// <summary>
    /// Add a member, reviving a removed membership if there is one. Requires
    /// <see cref="ManagePermission"/>.
    /// <para>
    /// When the request opens a new account, the generated password is mailed to it and is never
    /// in this response - read <c>reusedAccount</c> together with <c>emailSent</c> to know whether
    /// anyone has to intervene.
    /// </para>
    /// </summary>
    [HttpPost]
    [ProducesResponseType<CreateMemberResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<CreateMemberResponse> Create(
        string tenantType,
        string tenantCode,
        CreateMemberRequest request,
        CancellationToken cancellationToken)
    {
        var caller = await RequireAsync(ManagePermission, cancellationToken);

        return await memberService.CreateMemberAsync(
            caller, tenantType, tenantCode, request, cancellationToken);
    }

    /// <summary>Replace a member's roles. Requires <see cref="ManagePermission"/>.</summary>
    [HttpPut("{userId:int}/roles")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> UpdateRoles(
        string tenantType,
        string tenantCode,
        int userId,
        UpdateMemberRolesRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var caller = await RequireAsync(ManagePermission, cancellationToken);

        await memberService.UpdateMemberRolesAsync(
            caller,
            tenantType,
            tenantCode,
            userId,
            request.RoleIds,
            cancellationToken);

        return NoContent();
    }

    /// <summary>Suspend or reinstate a membership. Requires <see cref="ManagePermission"/>.</summary>
    [HttpPut("{userId:int}/status")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> UpdateStatus(
        string tenantType,
        string tenantCode,
        int userId,
        UpdateMemberStatusRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var caller = await RequireAsync(ManagePermission, cancellationToken);

        await memberService.UpdateMemberStatusAsync(
            caller,
            tenantType,
            tenantCode,
            userId,
            request.Status,
            cancellationToken);

        return NoContent();
    }

    /// <summary>
    /// Take a member out of the tenant. Requires <see cref="ManagePermission"/>.
    /// <para>
    /// A soft removal: the account is untouched, and adding the person again brings the same
    /// membership row back.
    /// </para>
    /// </summary>
    [HttpDelete("{userId:int}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Remove(
        string tenantType,
        string tenantCode,
        int userId,
        CancellationToken cancellationToken)
    {
        var caller = await RequireAsync(ManagePermission, cancellationToken);

        await memberService.RemoveMemberAsync(
            caller, tenantType, tenantCode, userId, cancellationToken);

        return NoContent();
    }

    /// <summary>
    /// Mint a new password for a member and mail it to them. Requires
    /// <see cref="ManagePermission"/>. External accounts only.
    /// </summary>
    [HttpPost("{userId:int}/reset-password")]
    [ProducesResponseType<ResetMemberPasswordResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ResetMemberPasswordResponse> ResetPassword(
        string tenantType,
        string tenantCode,
        int userId,
        CancellationToken cancellationToken)
    {
        var caller = await RequireAsync(ManagePermission, cancellationToken);

        return await memberService.ResetMemberPasswordAsync(
            caller, tenantType, tenantCode, userId, cancellationToken);
    }

    /// <summary>Reads the caller and refuses them unless they hold the named permission code.
    /// Returns the caller so no action reads the principal twice.</summary>
    private async Task<BackOfficeCaller> RequireAsync(
        string permissionCode, CancellationToken cancellationToken)
    {
        var caller = BackOfficeCallerReader.Read(User);
        await BackOfficePermissions.RequireAsync(snapshots, caller, permissionCode, cancellationToken);

        return caller;
    }
}
