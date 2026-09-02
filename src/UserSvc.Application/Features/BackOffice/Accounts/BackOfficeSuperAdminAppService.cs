using System.Globalization;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Accounts;

/// <summary>
/// The one write path for the platform super-administrator flag, and the two guards every other
/// module asks about it.
/// <para>
/// <b>The flag is an identity, not a breadth.</b> It hardcodes every permission, every menu and
/// both global data scopes wherever its holder acts, and it is exclusive with tenant membership -
/// a platform owner is not also "an administrator of company A". Data breadth is a different lever
/// on a different endpoint, and conflating the two is how someone who was meant to see more data
/// ends up owning the platform.
/// </para>
/// <para>
/// <b>Three rules here are not conveniences.</b> Only a super administrator may appoint or remove
/// one; the platform may never be left without an ACTIVE one; and every decision reads the flag
/// from the database rather than from a token claim, because a claim is minted from a state that
/// may have changed since - and the whole point of the flag is that revoking it takes effect now.
/// </para>
/// </summary>
public sealed class BackOfficeSuperAdminAppService(
    IBackendUserRepository users,
    ICurrentUser currentUser,
    IIamAuditLogRepository auditLog,
    IClock clock,
    IUnitOfWork unitOfWork,
    ILogger<BackOfficeSuperAdminAppService> logger)
{
    /// <summary>
    /// Whether this account holds the platform identity, read from its row.
    /// <para>
    /// Non-positive ids and missing rows are false rather than an error: every caller is asking a
    /// yes/no authorization question, and the only safe answer to "I cannot tell" is no.
    /// </para>
    /// </summary>
    public async Task<bool> IsPlatformSuperAdminAsync(int userId, CancellationToken cancellationToken)
    {
        if (userId <= 0)
        {
            return false;
        }

        var account = await users.ReadByIdAsync(userId, cancellationToken);

        return account?.IsSuperAdmin == true;
    }

    /// <summary>
    /// Refuses unless the current caller holds the platform identity.
    /// <para>
    /// Exported because several other modules need exactly this check before their own writes, and
    /// a second copy of it would be a second place for the flag to be trusted from a claim.
    /// </para>
    /// </summary>
    /// <exception cref="ForbiddenException">The caller is anonymous or is not a super
    /// administrator. 403, not 400: nothing about the request can be corrected.</exception>
    public async Task AssertPlatformSuperAdminAsync(CancellationToken cancellationToken)
    {
        var callerId = currentUser.UserId ?? 0;

        if (!await IsPlatformSuperAdminAsync(callerId, cancellationToken))
        {
            throw new ForbiddenException(
                ErrorCodes.SuperAdminRequired,
                "Only a platform super administrator can perform this action.");
        }
    }

    /// <summary>
    /// Refuses when the target account holds the platform identity. The guard every tenant-side
    /// write - adding a membership, binding a role, granting company or supplier access - must run
    /// before it touches an account.
    /// <para>
    /// It exists because the exclusivity has to be enforced from both directions. Promotion clears
    /// tenant bindings; without this, the next role assignment would quietly give them back, and
    /// the platform owner would start carrying a tenant's authority alongside their own.
    /// </para>
    /// </summary>
    /// <exception cref="NotFoundException">There is no such account.</exception>
    /// <exception cref="ConflictException">The account holds the platform identity, which conflicts
    /// with holding anything inside a tenant.</exception>
    public async Task AssertNotSuperAdminTargetAsync(int userId, CancellationToken cancellationToken)
    {
        var account = await users.ReadByIdAsync(userId, cancellationToken)
                      ?? throw new NotFoundException(
                          ErrorCodes.MemberNotFound, "That back-office account does not exist.");

        if (account.IsSuperAdmin)
        {
            throw new ConflictException(
                ErrorCodes.SuperAdminExclusive,
                "The platform super administrator cannot hold tenant roles or company and supplier access.");
        }
    }

    /// <summary>
    /// Grants or revokes the platform identity.
    /// <para>
    /// <b>Idempotent by design.</b> Asking for the state the account is already in returns success
    /// without writing, auditing or invalidating anyone's tokens - a retried request, or two
    /// operators clicking the same switch, must not sign someone out twice for nothing.
    /// </para>
    /// <para>
    /// <b>Revocation is refused when it would leave the platform without an ACTIVE super
    /// administrator</b>, and that decision is made inside the UPDATE statement rather than here.
    /// Two concurrent revocations would otherwise each read "there are two of us" and each remove
    /// one, leaving nobody who can appoint a replacement - a state no endpoint in this service can
    /// recover from, because appointing one requires being one.
    /// </para>
    /// </summary>
    /// <exception cref="ForbiddenException">The caller is not a super administrator.</exception>
    /// <exception cref="NotFoundException">There is no such account.</exception>
    /// <exception cref="BadRequestException">The account is not active, so it cannot be granted the
    /// identity.</exception>
    /// <exception cref="ConflictException">The account is the platform's last active super
    /// administrator.</exception>
    public async Task SetSuperAdminAsync(
        int targetUserId,
        SetSuperAdminRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Before the target is even read: whether this endpoint may be used at all is not a
        // question about the target, and answering "no such user" to someone who is not allowed to
        // ask would still tell them which ids exist.
        await AssertPlatformSuperAdminAsync(cancellationToken);

        var target = await users.ReadByIdAsync(targetUserId, cancellationToken)
                     ?? throw new NotFoundException(
                         ErrorCodes.NotFound, "That back-office account does not exist.");

        // The validator refuses a null Enabled, so this default is only ever reached by a direct
        // caller. False is the safe reading of "unstated" for a flag that grants the platform.
        var enabled = request.Enabled ?? false;

        if (enabled == target.IsSuperAdmin)
        {
            return;
        }

        if (enabled)
        {
            await GrantAsync(targetUserId, target.IsActive(), cancellationToken);
        }
        else
        {
            await RevokeAsync(targetUserId, cancellationToken);
        }
    }

    private async Task GrantAsync(int targetUserId, bool targetIsActive, CancellationToken cancellationToken)
    {
        if (!targetIsActive)
        {
            // A disabled or pending account cannot sign in, so granting it the platform identity
            // creates a dormant owner nobody can use - and one that the last-active-super guard
            // will then refuse to count when someone tries to revoke the real one.
            throw new BadRequestException(
                ErrorCodes.BadRequest,
                "Only an active account can be made a platform super administrator.");
        }

        await unitOfWork.ExecuteInTransactionAsync(
            async ct =>
            {
                if (!await users.GrantSuperAdminAsync(targetUserId, Actor, ct))
                {
                    throw new NotFoundException(
                        ErrorCodes.NotFound, "That back-office account does not exist.");
                }

                // Same transaction as the grant: the promoted account's outstanding tokens describe
                // an authority surface that no longer matches its row, and a bump that committed
                // separately could be the half that failed.
                await users.IncrementTokenVersionAsync([targetUserId], ct);
            },
            cancellationToken);

        // KNOWN GAP - tenant bindings are not cleared here, because the tenant tables belong to a
        // module this service has not ported yet. The promotion is supposed to end every
        // membership the account holds, so that nothing survives to come silently back into force
        // when the identity is later revoked. Until that module lands, the exclusivity is enforced
        // in one direction only: AssertNotSuperAdminTargetAsync stops new bindings from being
        // created, so the gap can only affect an account that already had memberships when it was
        // promoted. This is logged rather than left silent, because it is the operator - not the
        // code - who has to check that today.
        logger.LogWarning(
            "Back-office account {BackendUserId} was granted the platform super-administrator "
            + "identity by {ActorUserId}. Existing tenant memberships were NOT cleared: that step "
            + "arrives with the tenant module. Verify by hand that this account holds none.",
            targetUserId,
            currentUser.UserId);

        await WriteAuditAsync(IamAuditActions.SuperAdminGrant, targetUserId, cancellationToken);
    }

    private async Task RevokeAsync(int targetUserId, CancellationToken cancellationToken)
    {
        var revoked = false;

        await unitOfWork.ExecuteInTransactionAsync(
            async ct =>
            {
                revoked = await users.RevokeSuperAdminIfAnotherActiveExistsAsync(targetUserId, Actor, ct);

                if (!revoked)
                {
                    // The statement writes nothing both when it refuses and when there was nothing
                    // to clear, so the two are told apart by re-reading - untracked, or the answer
                    // would come from the instance read before the statement ran.
                    var current = await users.ReadByIdAsync(targetUserId, ct);

                    if (current is null || !current.IsSuperAdmin)
                    {
                        // Someone else revoked it first. A lost race on an idempotent operation is
                        // a success: the caller asked for a state, and the account is in it.
                        logger.LogInformation(
                            "The super-administrator identity of back-office account "
                            + "{BackendUserId} had already been revoked.",
                            targetUserId);

                        return;
                    }

                    throw new ConflictException(
                        ErrorCodes.SuperAdminRequired,
                        "This is the platform's last active super administrator. Appoint another "
                        + "one before revoking this account.");
                }

                await users.IncrementTokenVersionAsync([targetUserId], ct);
            },
            cancellationToken);

        if (!revoked)
        {
            // Nothing was written - either the caller lost the race, or the flag was already off.
            // An audit row here would record a change that did not happen on this request.
            return;
        }

        logger.LogWarning(
            "Back-office account {BackendUserId} lost the platform super-administrator "
            + "identity, revoked by {ActorUserId}.",
            targetUserId,
            currentUser.UserId);

        await WriteAuditAsync(IamAuditActions.SuperAdminRevoke, targetUserId, cancellationToken);
    }

    /// <summary>
    /// Records a grant or a revocation, <b>after the transaction has committed and always best
    /// effort</b>.
    /// <para>
    /// After, because a failed INSERT poisons an open PostgreSQL transaction - swallowing the audit
    /// failure inside one would roll back the change it was meant to record. Best effort, because
    /// the change is already committed and throwing here would tell the operator the promotion
    /// failed while the account holds the platform.
    /// </para>
    /// <para>
    /// It is logged at Error rather than Warning when it fails: an unrecorded change of who owns the
    /// platform is the single entry in this trail nobody can afford to be missing.
    /// </para>
    /// </summary>
    private async Task WriteAuditAsync(string action, int targetUserId, CancellationToken cancellationToken)
    {
        var entry = new IamAuditLog
        {
            // Zero when the call came from outside a request - a background or direct caller. The
            // row still has to exist: "somebody promoted this account" is worth more than nothing.
            ActorUserId = currentUser.UserId ?? 0,

            // No name: ICurrentUser carries claims, not a profile, and a second read to decorate an
            // audit row is not worth a round trip on this path.
            TenantType = IamAuditTenantTypes.Platform,
            TenantCode = string.Empty,
            Action = action,
            TargetType = IamAuditTargetTypes.User,
            TargetId = targetUserId.ToString(CultureInfo.InvariantCulture),
            CreatedAt = clock.UtcNow,
        };

        try
        {
            await auditLog.AppendAsync(entry, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(
                ex,
                "{Action} on back-office account {BackendUserId} committed, but its audit entry "
                + "could not be written. The trail is missing a change of platform ownership.",
                action,
                targetUserId);
        }
    }

    /// <summary>
    /// What lands in the row's <c>updated_by</c> column. The caller's id, or <c>system</c> when
    /// there is none - which on this service's paths means a background or direct call, since every
    /// route into it is authenticated.
    /// </summary>
    private string Actor =>
        currentUser.UserId is { } id ? id.ToString(CultureInfo.InvariantCulture) : "system";
}
