using System.Globalization;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac.Contracts;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>
/// The two platform-level levers: whole-dimension data access, and the platform super-administrator
/// flag itself.
/// <para>
/// They are different things and were separated deliberately. Whole-dimension access shapes data
/// <b>breadth</b> - a membership row and the roles on it. The super-administrator flag is an
/// <b>identity</b> on the account row: every permission, every menu and global breadth in both
/// dimensions, hard-coded. Stripping both dimensions can no longer demote the platform owner, which
/// is the trap the retired "not the last super administrator" guard existed to cover.
/// </para>
/// </summary>
public sealed class SuperAdminAppService(
    IBackOfficeUserDirectory users,
    IGlobalAccessMemberships memberships,
    IRoleRepository roles,
    AdminScopeService adminScopes,
    RoleDelegationService delegation,
    IamAuditWriter audit,
    IAuthzConvergence convergence,
    IUnitOfWork unitOfWork)
{
    /// <summary>
    /// Set an account's whole-dimension access, both dimensions in one call.
    /// </summary>
    public async Task SetUserGlobalAccessAsync(
        IBackOfficeCaller caller,
        int userId,
        SetGlobalAccessRequest request,
        CancellationToken cancellationToken)
    {
        // Unconditional, and not conditional on the flag actually changing. An earlier version ran the
        // check per dimension and only when scope_all flipped, which left the endpoint's other half -
        // rebinding roles on an existing whole-dimension row - guarded by nothing but an ordinary
        // route permission. That was enough for a caller with no global standing at all to bind an
        // administrator role onto their own global membership, or strip somebody else's.
        await adminScopes.AssertCanGrantWholeDimensionAsync(caller, string.Empty, cancellationToken);

        var target = await users.FindFlagsAsync(userId, cancellationToken)
                     ?? throw new NotFoundException(ErrorCodes.NotFound, $"User {userId} was not found.");

        if (target.IsSuperAdmin && (request.Company.ScopeAll || request.Supplier.ScopeAll))
        {
            // Only the granting direction is refused. Turning a dimension off stays available, so the
            // rows left behind before a promotion can still be cleaned up.
            throw new BadRequestException(
                ErrorCodes.SuperAdminExclusive,
                "The platform super administrator cannot hold tenant roles or company/supplier access.");
        }

        var dimensions = new[]
        {
            (TenantType: TenantTypes.Company, Dimension: request.Company),
            (TenantType: TenantTypes.Supplier, Dimension: request.Supplier),
        };

        // Validate outside the transaction, so a bad role list fails fast without opening one.
        foreach (var (tenantType, dimension) in dimensions)
        {
            if (!dimension.ScopeAll || dimension.RoleIds.Count == 0)
            {
                continue;
            }

            var wanted = CallerFacts.DedupeSort(dimension.RoleIds);
            var found = await roles.FindByIdsAsync(wanted, cancellationToken);
            if (found.Count != wanted.Count)
            {
                throw new BadRequestException(ErrorCodes.BadRequest, "One or more role IDs are invalid.");
            }

            await delegation.AssertRolesFitTenantTypeAsync(tenantType, wanted, cancellationToken);
            RoleDelegationService.AssertNoTenantOwnedRoles(found);
        }

        await unitOfWork.ExecuteInTransactionAsync(async ct =>
        {
            foreach (var (tenantType, dimension) in dimensions)
            {
                if (dimension.ScopeAll)
                {
                    await memberships.GrantWholeDimensionAsync(
                        userId, tenantType, CallerFacts.DedupeSort(dimension.RoleIds), ct);
                }
                else
                {
                    await memberships.RevokeWholeDimensionAsync(userId, tenantType, ct);
                }
            }

            // Inside the transaction, after both dimensions: the account's existing sessions must not
            // outlive a breadth change that has already committed.
            await users.IncrementTokenVersionAsync([userId], ct);
        }, cancellationToken);

        await audit.WriteAsync(
            caller,
            IamAuditActions.MemberRolesUpdate,
            IamAuditTargetTypes.Member,
            userId.ToString(CultureInfo.InvariantCulture),
            before: null,
            after: new
            {
                Company = new { request.Company.ScopeAll, RoleIds = CallerFacts.DedupeSort(request.Company.RoleIds) },
                Supplier = new { request.Supplier.ScopeAll, RoleIds = CallerFacts.DedupeSort(request.Supplier.RoleIds) },
            },
            cancellationToken);

        // Invalidate, not bump. Every one of these three paths has already incremented
        // token_version inside the transaction above, where it belongs; calling the bump here
        // would increment the generation counter a second time, outside that transaction.
        // Measured before this was corrected: one PUT /users/{id}/global-access moved the
        // column from 2 to 4. What is still owed after the commit is the other half - dropping
        // the cached authority faces, which the committed bump does not reach - and that is
        // exactly what this call is (spec 08 §3.11: BumpCacheInvalidate after the commit,
        // IncrementTokenVersion inside it).
        await convergence.InvalidateAuthzAsync([userId], cancellationToken);
    }

    /// <summary>
    /// Grant or revoke the platform super-administrator flag.
    /// <para>
    /// Self-revocation is allowed under the same guard. The guard is an atomic update - the existence
    /// check and the write are one statement - so concurrent revocations cannot race the platform down
    /// to zero owners.
    /// </para>
    /// </summary>
    public async Task SetSuperAdminAsync(
        IBackOfficeCaller caller,
        int userId,
        SetSuperAdminRequest request,
        CancellationToken cancellationToken)
    {
        await adminScopes.AssertPlatformSuperAdminAsync(caller, cancellationToken);

        var target = await users.FindFlagsAsync(userId, cancellationToken)
                     ?? throw new NotFoundException(ErrorCodes.NotFound, "User was not found.");

        var enabled = request.Enabled ?? false;
        if (enabled == target.IsSuperAdmin)
        {
            // Idempotent: no write, no audit entry, no token bump.
            return;
        }

        if (enabled)
        {
            await GrantAsync(caller, userId, target, cancellationToken);
            return;
        }

        await RevokeAsync(caller, userId, cancellationToken);
    }

    private async Task GrantAsync(
        IBackOfficeCaller caller,
        int userId,
        BackOfficeUserFlags target,
        CancellationToken cancellationToken)
    {
        if (!target.IsActive())
        {
            // A disabled account cannot sign in, so granting it the platform identity would only
            // create a dormant owner nobody can use.
            throw new BadRequestException(
                ErrorCodes.BadRequest,
                "Cannot grant super administrator to an account that is not active.");
        }

        IReadOnlyList<ClearedMembership> cleared = [];

        await unitOfWork.ExecuteInTransactionAsync(async ct =>
        {
            await users.GrantSuperAdminAsync(userId, ct);
            cleared = await memberships.ClearAllMembershipsAsync(userId, ct);
            await users.IncrementTokenVersionAsync([userId], ct);
        }, cancellationToken);

        await audit.WriteAsync(
            caller,
            IamAuditActions.SuperAdminGrant,
            IamAuditTargetTypes.User,
            userId.ToString(CultureInfo.InvariantCulture),
            cleared.Count > 0 ? new { ClearedMemberships = cleared } : null,
            after: null,
            cancellationToken);

        // Invalidate, not bump. Every one of these three paths has already incremented
        // token_version inside the transaction above, where it belongs; calling the bump here
        // would increment the generation counter a second time, outside that transaction.
        // Measured before this was corrected: one PUT /users/{id}/global-access moved the
        // column from 2 to 4. What is still owed after the commit is the other half - dropping
        // the cached authority faces, which the committed bump does not reach - and that is
        // exactly what this call is (spec 08 §3.11: BumpCacheInvalidate after the commit,
        // IncrementTokenVersion inside it).
        await convergence.InvalidateAuthzAsync([userId], cancellationToken);
    }

    private async Task RevokeAsync(
        IBackOfficeCaller caller,
        int userId,
        CancellationToken cancellationToken)
    {
        var revoked = false;

        await unitOfWork.ExecuteInTransactionAsync(async ct =>
        {
            if (await users.TryRevokeSuperAdminAsync(userId, ct))
            {
                revoked = true;
                await users.IncrementTokenVersionAsync([userId], ct);
                return;
            }

            // Re-read to tell the two failures apart. Losing a race to a concurrent revocation is an
            // idempotent success, not a refusal - the flag the caller wanted gone is gone.
            var fresh = await users.FindFlagsAsync(userId, ct);
            if (fresh is not null && !fresh.IsSuperAdmin)
            {
                return;
            }

            throw new BadRequestException(
                ErrorCodes.SuperAdminRequired,
                "This is the platform's last active super administrator; appoint another one before revoking.");
        }, cancellationToken);

        if (!revoked)
        {
            return;
        }

        await audit.WriteAsync(
            caller,
            IamAuditActions.SuperAdminRevoke,
            IamAuditTargetTypes.User,
            userId.ToString(CultureInfo.InvariantCulture),
            before: null,
            after: null,
            cancellationToken);

        // Invalidate, not bump. Every one of these three paths has already incremented
        // token_version inside the transaction above, where it belongs; calling the bump here
        // would increment the generation counter a second time, outside that transaction.
        // Measured before this was corrected: one PUT /users/{id}/global-access moved the
        // column from 2 to 4. What is still owed after the commit is the other half - dropping
        // the cached authority faces, which the committed bump does not reach - and that is
        // exactly what this call is (spec 08 §3.11: BumpCacheInvalidate after the commit,
        // IncrementTokenVersion inside it).
        await convergence.InvalidateAuthzAsync([userId], cancellationToken);
    }
}
