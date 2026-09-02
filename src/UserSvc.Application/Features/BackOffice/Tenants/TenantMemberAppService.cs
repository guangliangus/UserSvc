using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Features.BackOffice.Tenants;

/// <summary>
/// The tenant member surface: list, add or revive, re-role, suspend, remove, reset password.
/// <para>
/// Every write in here does the same five things, and skipping any one of them is a defect rather
/// than a shortcut. It serializes on the tenant's advisory lock, so two administrators clicking at
/// once cannot both pass the last-administrator check. It re-checks the caller's standing against
/// the database instead of the token. It runs the delegation ceiling, so nobody hands out more
/// than they hold. It writes one audit row. And it bumps the target's token version, so the change
/// lands on their next request instead of at their next sign-in.
/// </para>
/// <para>
/// A note on shape: this service depends on several ports that other slices own - the role
/// catalogue, the account directory, the delegation ceiling. They are declared here as the
/// narrowest projection tenancy needs, so that this slice compiles and is testable before those
/// slices land, and so that their table shapes are not pinned by this one.
/// </para>
/// </summary>
public sealed class TenantMemberAppService(
    ITenantMemberRepository members,
    IUserTenantRoleRepository bindings,
    IRoleDirectory roles,
    IRoleDelegationService delegation,
    IAdminStandingService standing,
    IBackOfficeAccountDirectory accounts,
    IBackOfficeUserProvisioner provisioner,
    ICredentialEmailSender credentialEmails,
    IIamAuditLog auditLog,
    ITokenVersionCache tokenVersions,
    PasswordHasher passwordHasher,
    IUnitOfWork unitOfWork,
    IClock clock,
    ILogger<TenantMemberAppService> logger)
{
    private const int DefaultPageSize = 20;
    private const int MaxPageSize = 100;

    /// <summary>Audit payloads omit what an action did not touch, so a row shows the change and
    /// not a diff of everything.</summary>
    private static readonly JsonSerializerOptions AuditJson = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    // ---------------------------------------------------------------------------- read

    /// <summary>
    /// One page of a tenant's roster.
    /// <para>
    /// Note the read gate is <b>not</b> the write gate. Reading the roster of the tenant you are
    /// acting in needs no administrator standing, because a plain member with the read permission
    /// is meant to be able to do it. Reading some <i>other</i> tenant's roster - only a global
    /// caller can even ask - does need it: names, decrypted e-mail addresses and role bindings are
    /// not something a read permission on one dimension should hand over for the other.
    /// </para>
    /// </summary>
    public async Task<TenantMemberListResponse> ListMembersAsync(
        BackOfficeCaller caller,
        string tenantType,
        string tenantCode,
        string? status,
        string? keyword,
        int page,
        int pageSize,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);

        var type = NormalizeTenantRef(tenantType, tenantCode);
        await AssertCanReadTenantRosterAsync(caller, type, tenantCode, cancellationToken);

        var normalizedPage = page < 1 ? 1 : page;
        var normalizedSize = pageSize <= 0 ? DefaultPageSize : Math.Min(pageSize, MaxPageSize);

        // A keyword is resolved to account ids first, and an empty result stays empty: "matched
        // nobody" must not degrade into "no filter at all", which would answer a failed search with
        // the whole roster.
        var matchedUserIds = string.IsNullOrWhiteSpace(keyword)
            ? null
            : await accounts.SearchUserIdsAsync(keyword.Trim(), cancellationToken);

        var query = new TenantMemberQuery(
            type, tenantCode, status ?? string.Empty, matchedUserIds, normalizedPage, normalizedSize);

        var roster = await members.ListByTenantAsync(query, cancellationToken);

        var memberIds = roster.Items.Select(m => m.Id).ToList();
        var userIds = roster.Items.Select(m => m.UserId).Distinct().ToList();

        IReadOnlyDictionary<int, IReadOnlyList<int>> roleIdsByMember = memberIds.Count == 0
            ? new Dictionary<int, IReadOnlyList<int>>()
            : await bindings.ListRoleIdsByMemberIdsAsync(memberIds, cancellationToken);

        var distinctRoleIds = roleIdsByMember.Values.SelectMany(ids => ids).Distinct().Order().ToList();
        var roleById = (await roles.FindByIdsAsync(distinctRoleIds, cancellationToken))
            .ToDictionary(role => role.Id);

        var accountById = (await accounts.ListByIdsAsync(userIds, cancellationToken))
            .ToDictionary(account => account.Id);
        var emailByUser = await accounts.ListPrimaryEmailsAsync(userIds, cancellationToken);

        var items = roster.Items.Select(member =>
        {
            var account = accountById.GetValueOrDefault(member.UserId);
            var email = emailByUser.GetValueOrDefault(member.UserId, string.Empty);
            var boundRoleIds = roleIdsByMember.GetValueOrDefault(member.Id, []);

            return new TenantMemberResponse
            {
                UserId = member.UserId,
                Nickname = account is null
                    ? string.Empty
                    : BackOfficeNames.Display(account.FirstName, account.LastName, account.Nickname),
                Email = email,
                StaffCode = account?.StaffCode ?? string.Empty,
                DeptName = member.DeptName ?? string.Empty,
                IsAdmin = member.IsAdmin,

                // Bound order, not catalogue order: the roster shows the bindings as they were
                // made. Ids the catalogue no longer resolves are dangling and simply drop out.
                Roles = [.. boundRoleIds
                    .Where(roleById.ContainsKey)
                    .Select(id => new TenantRoleResponse
                    {
                        Id = id,
                        Code = roleById[id].Code,
                        Name = roleById[id].Name,
                    })],
                Status = member.Status,
            };
        }).ToList();

        return new TenantMemberListResponse
        {
            Items = items,
            Total = roster.Total,
            Page = normalizedPage,
            PageSize = normalizedSize,
        };
    }

    // --------------------------------------------------------------------------- writes

    /// <summary>
    /// Add somebody to a tenant, or bring a removed membership back.
    /// <para>
    /// The delegation gates run <b>before</b> the transaction on purpose: they need no locks, they
    /// are the most common rejection, and failing them after an account has been provisioned would
    /// mean rolling an invitation back for a reason that was knowable up front.
    /// </para>
    /// </summary>
    public async Task<CreateMemberResponse> CreateMemberAsync(
        BackOfficeCaller caller,
        string tenantType,
        string tenantCode,
        CreateMemberRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(request);

        var type = NormalizeTenantRef(tenantType, tenantCode);
        AuthorizeTenantAccess(caller, type, tenantCode);
        await AssertCanManageMembersAsync(caller, type, tenantCode, cancellationToken);
        ValidateTargetSelector(request);

        var callerUserId = caller.RequireUserId();
        var requestedRoleIds = Distinct(request.RoleIds);

        // Category before ceiling. A role for the wrong kind of tenant has to be refused for its
        // own reason: "outside your delegable range" is untrue for a super administrator, who has
        // no range, and no amount of authority makes a company role fit a supplier.
        await AssertRolesFitTenantTypeAsync(type, requestedRoleIds, cancellationToken);
        var delegable = await DelegableRoleSetAsync(callerUserId, type, tenantCode, cancellationToken);
        await AssertRolesDelegableAsync(delegable, requestedRoleIds, cancellationToken);

        var stamp = Stamp(caller);
        var memberId = 0;
        var targetUserId = 0;
        var reusedAccount = false;
        var initialPassword = string.Empty;
        var revivedFrom = string.Empty;
        var memberStatus = TenantMemberStatuses.Active;
        var memberIsAdmin = false;
        var memberDeptName = string.Empty;

        await unitOfWork.ExecuteInTransactionAsync(async token =>
        {
            var target = await provisioner.ResolveOrProvisionAsync(
                request.UserId,
                request.NewUser is null
                    ? null
                    : new NewAccountRequest(
                        request.NewUser.Email,
                        request.NewUser.Nickname,
                        request.NewUser.FirstName,
                        request.NewUser.LastName),
                token);

            targetUserId = target.UserId;
            reusedAccount = target.ReusedAccount;
            initialPassword = target.InitialPassword;

            // Only a reused account can already be the platform super administrator; one created a
            // moment ago cannot be. That identity is exclusive with holding tenant access.
            if (reusedAccount)
            {
                await AssertNotSuperAdminTargetAsync(targetUserId, token);
            }

            await members.AcquireTenantLockAsync(type, tenantCode, token);

            var (member, previousStatus) = await UpsertActiveMembershipAsync(
                targetUserId, type, tenantCode, request.DeptName, stamp, token);

            memberId = member.Id;

            await bindings.ReplaceForMemberAsync(
                member.Id, requestedRoleIds, stamp, clock.UtcNow, token);
            await SyncMemberAdminFlagAsync(member, requestedRoleIds, stamp, token);
            await accounts.IncrementTokenVersionAsync(targetUserId, token);

            // Only captured here. The audit row itself is written after the commit - see
            // WriteMemberAuditAsync for why it cannot be written inside.
            revivedFrom = previousStatus;
            memberStatus = member.Status;
            memberIsAdmin = member.IsAdmin;
            memberDeptName = member.DeptName ?? string.Empty;
        },
        cancellationToken);

        await WriteMemberAuditAsync(
            caller,
            type,
            tenantCode,
            IamAuditActions.MemberAdd,
            targetUserId,

            // A first-time join has no prior state; a revival does, and "removed member
            // reinstated" is a different event from "member added".
            revivedFrom.Length == 0 ? null : new MemberAuditSnapshot { Status = revivedFrom },
            new MemberAuditSnapshot
            {
                Status = memberStatus,
                IsAdmin = memberIsAdmin,
                RoleCodes = await RoleCodesAsync(requestedRoleIds, cancellationToken),
                DeptName = memberDeptName.Length == 0 ? null : memberDeptName,
            },
            cancellationToken);

        // After the commit, never inside it. Sending from inside would hold the tenant's advisory
        // lock across an HTTP call, and could mail credentials for an account a rollback then
        // un-created.
        var emailSent = false;
        if (initialPassword.Length > 0 && request.NewUser is not null)
        {
            emailSent = await credentialEmails.SendInitialPasswordAsync(
                targetUserId,
                request.NewUser.Email,
                MemberDisplayName(request.NewUser),
                initialPassword,
                cancellationToken);
        }

        await tokenVersions.InvalidateAsync(targetUserId, cancellationToken);

        return new CreateMemberResponse
        {
            MemberId = memberId,
            UserId = targetUserId,
            ReusedAccount = reusedAccount,
            EmailSent = emailSent,
        };
    }

    /// <summary>
    /// Replace a member's roles.
    /// <para>
    /// This is a whole-set replace, which is why the bindings the caller may not delegate are
    /// merged back in rather than dropped: a role granted by somebody more senior must not
    /// evaporate because a junior administrator edited an unrelated part of the same member.
    /// </para>
    /// </summary>
    public async Task UpdateMemberRolesAsync(
        BackOfficeCaller caller,
        string tenantType,
        string tenantCode,
        int targetUserId,
        IReadOnlyList<int> roleIds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);

        var type = NormalizeTenantRef(tenantType, tenantCode);
        AuthorizeTenantAccess(caller, type, tenantCode);
        await AssertCanManageMembersAsync(caller, type, tenantCode, cancellationToken);

        var callerUserId = caller.RequireUserId();
        var requestedRoleIds = Distinct(roleIds);

        await AssertRolesFitTenantTypeAsync(type, requestedRoleIds, cancellationToken);

        // One ceiling resolution serves both halves: what may be submitted, and what an overwrite
        // must leave alone.
        var delegable = await DelegableRoleSetAsync(callerUserId, type, tenantCode, cancellationToken);
        await AssertRolesDelegableAsync(delegable, requestedRoleIds, cancellationToken);

        var stamp = Stamp(caller);
        var wasAdmin = false;
        var stillAdmin = false;
        IReadOnlyList<int> currentRoleIds = [];
        IReadOnlyList<int> finalRoleIds = [];

        await unitOfWork.ExecuteInTransactionAsync(async token =>
        {
            await members.AcquireTenantLockAsync(type, tenantCode, token);
            var member = await FindManageableMemberAsync(targetUserId, type, tenantCode, token);

            // Normally unreachable - the super administrator holds no memberships - and kept for
            // the row left behind by an account promoted before that rule existed.
            await AssertNotSuperAdminTargetAsync(targetUserId, token);
            AssertAdminMemberNotPeerWritable(caller, member);

            // Read before the replace overwrites them; the codes they map to are resolved after
            // the commit, where the audit row is written.
            currentRoleIds = [.. (await bindings.ListByMemberIdAsync(member.Id, token))
                .Select(binding => binding.RoleId)];
            wasAdmin = member.IsAdmin;

            var preserved = await RoleIdsOutsideCeilingAsync(currentRoleIds, type, delegable, token);
            finalRoleIds = Union(requestedRoleIds, preserved);

            stillAdmin = await ContainsAdminRoleAsync(finalRoleIds, token);
            if (!stillAdmin)
            {
                await AssertNotLastAdminAsync(
                    callerUserId,
                    member,
                    type,
                    tenantCode,
                    "Transfer the tenant administrator before removing the last administrator's admin role.",
                    token);
            }

            await bindings.ReplaceForMemberAsync(member.Id, finalRoleIds, stamp, clock.UtcNow, token);
            await ApplyMemberAdminFlagAsync(member, stillAdmin, stamp, token);
            await accounts.IncrementTokenVersionAsync(targetUserId, token);
        },
        cancellationToken);

        await WriteMemberAuditAsync(
            caller,
            type,
            tenantCode,
            IamAuditActions.MemberRolesUpdate,
            targetUserId,
            new MemberAuditSnapshot
            {
                IsAdmin = wasAdmin,
                RoleCodes = await RoleCodesAsync(currentRoleIds, cancellationToken),
            },
            new MemberAuditSnapshot
            {
                IsAdmin = stillAdmin,
                RoleCodes = await RoleCodesAsync(finalRoleIds, cancellationToken),
            },
            cancellationToken);

        await tokenVersions.InvalidateAsync(targetUserId, cancellationToken);
    }

    /// <summary>Suspend or reinstate a membership. REMOVED is refused here - it has its own verb
    /// and its own audit action.</summary>
    public async Task UpdateMemberStatusAsync(
        BackOfficeCaller caller,
        string tenantType,
        string tenantCode,
        int targetUserId,
        string status,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);

        var type = NormalizeTenantRef(tenantType, tenantCode);

        if (status is not (TenantMemberStatuses.Active or TenantMemberStatuses.Disabled))
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest,
                "Status must be ACTIVE or DISABLED. Use the remove action to take a member out of a tenant.");
        }

        AuthorizeTenantAccess(caller, type, tenantCode);
        await AssertCanManageMembersAsync(caller, type, tenantCode, cancellationToken);

        var callerUserId = caller.RequireUserId();
        var stamp = Stamp(caller);
        var previousStatus = string.Empty;

        await unitOfWork.ExecuteInTransactionAsync(async token =>
        {
            await members.AcquireTenantLockAsync(type, tenantCode, token);
            var member = await FindManageableMemberAsync(targetUserId, type, tenantCode, token);

            // Refused in both directions: reinstating an administrator somebody more senior
            // suspended is just as much of an end run around the transfer flow as suspending one.
            AssertAdminMemberNotPeerWritable(caller, member);

            if (status == TenantMemberStatuses.Disabled)
            {
                await AssertNotLastAdminAsync(
                    callerUserId,
                    member,
                    type,
                    tenantCode,
                    "Transfer the tenant administrator before disabling the last administrator.",
                    token);
            }

            previousStatus = member.Status;
            member.Status = status;
            Touch(member, stamp);
            await unitOfWork.SaveChangesAsync(token);

            await accounts.IncrementTokenVersionAsync(targetUserId, token);
        },
        cancellationToken);

        await WriteMemberAuditAsync(
            caller,
            type,
            tenantCode,
            IamAuditActions.MemberStatusUpdate,
            targetUserId,
            new MemberAuditSnapshot { Status = previousStatus },
            new MemberAuditSnapshot { Status = status },
            cancellationToken);

        await tokenVersions.InvalidateAsync(targetUserId, cancellationToken);
    }

    /// <summary>
    /// Take a member out of a tenant. A soft delete: the account is untouched and the row can be
    /// revived by adding the person again.
    /// <para>
    /// The role bindings are deliberately left in place. They are not authority any more - the
    /// membership is what carries that - and a revival re-sets them anyway; deleting them would
    /// only destroy the evidence of what this person used to be able to do.
    /// </para>
    /// </summary>
    public async Task RemoveMemberAsync(
        BackOfficeCaller caller,
        string tenantType,
        string tenantCode,
        int targetUserId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);

        var type = NormalizeTenantRef(tenantType, tenantCode);
        AuthorizeTenantAccess(caller, type, tenantCode);
        await AssertCanManageMembersAsync(caller, type, tenantCode, cancellationToken);

        var callerUserId = caller.RequireUserId();
        var stamp = Stamp(caller);
        var previousStatus = string.Empty;
        var wasAdmin = false;
        IReadOnlyList<int> previousRoleIds = [];

        await unitOfWork.ExecuteInTransactionAsync(async token =>
        {
            await members.AcquireTenantLockAsync(type, tenantCode, token);
            var member = await FindManageableMemberAsync(targetUserId, type, tenantCode, token);

            AssertAdminMemberNotPeerWritable(caller, member);
            await AssertNotLastAdminAsync(
                callerUserId,
                member,
                type,
                tenantCode,
                "Transfer the tenant administrator before removing the last administrator.",
                token);

            // Captured before the write. By the time anyone reads this log the bindings may be
            // gone, and the question it has to answer is "what access did this take away".
            previousStatus = member.Status;
            wasAdmin = member.IsAdmin;
            previousRoleIds = [.. (await bindings.ListByMemberIdAsync(member.Id, token))
                .Select(binding => binding.RoleId)];

            member.Status = TenantMemberStatuses.Removed;
            Touch(member, stamp);
            await unitOfWork.SaveChangesAsync(token);

            await accounts.IncrementTokenVersionAsync(targetUserId, token);
        },
        cancellationToken);

        await WriteMemberAuditAsync(
            caller,
            type,
            tenantCode,
            IamAuditActions.MemberRemove,
            targetUserId,
            new MemberAuditSnapshot
            {
                Status = previousStatus,
                IsAdmin = wasAdmin,
                RoleCodes = await RoleCodesAsync(previousRoleIds, cancellationToken),
            },
            new MemberAuditSnapshot { Status = TenantMemberStatuses.Removed },
            cancellationToken);

        await tokenVersions.InvalidateAsync(targetUserId, cancellationToken);
    }

    /// <summary>
    /// Mint a new password for a member and mail it to them.
    /// <para>
    /// External accounts only: an internal one authenticates through the staff directory and has
    /// no local password a reset could replace. And a super administrator's password can only be
    /// reset by another super administrator - minting a password is a complete takeover of an
    /// account, and that identity must not be reachable by an administrator of any tenant it
    /// happens to belong to.
    /// </para>
    /// </summary>
    public async Task<ResetMemberPasswordResponse> ResetMemberPasswordAsync(
        BackOfficeCaller caller,
        string tenantType,
        string tenantCode,
        int targetUserId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);

        var type = NormalizeTenantRef(tenantType, tenantCode);
        AuthorizeTenantAccess(caller, type, tenantCode);
        await AssertCanManageMembersAsync(caller, type, tenantCode, cancellationToken);

        var callerUserId = caller.RequireUserId();
        var newPassword = string.Empty;
        var email = string.Empty;
        var displayName = string.Empty;

        await unitOfWork.ExecuteInTransactionAsync(async token =>
        {
            await members.AcquireTenantLockAsync(type, tenantCode, token);
            var member = await FindManageableMemberAsync(targetUserId, type, tenantCode, token);

            var account = await accounts.FindAsync(member.UserId, token)
                          ?? throw new NotFoundException(
                              ErrorCodes.MemberNotFound, "The member's account no longer exists.");

            if (account.Origin != BackOfficeAccountStates.ExternalOrigin)
            {
                throw new BadRequestException(
                    ErrorCodes.BadRequest,
                    "Password reset is only available for external accounts. Internal staff accounts "
                    + "authenticate through the staff directory.");
            }

            if (account.IsSuperAdmin
                && !await standing.IsPlatformSuperAdminAsync(callerUserId, token))
            {
                throw new ForbiddenException(
                    ErrorCodes.SuperAdminRequired,
                    "Only the platform super administrator may reset a platform super administrator's password.");
            }

            newPassword = InitialPasswordGenerator.Generate();
            await accounts.SetPasswordHashAsync(
                member.UserId, passwordHasher.Hash(newPassword), PasswordHasher.AlgorithmName, token);

            // Existing sessions die with the old password rather than outliving it.
            await accounts.IncrementTokenVersionAsync(member.UserId, token);

            var emails = await accounts.ListPrimaryEmailsAsync([member.UserId], token);
            email = emails.TryGetValue(member.UserId, out var found) ? found : string.Empty;
            displayName = account.Nickname.Trim().Length > 0
                ? account.Nickname.Trim()
                : BackOfficeNames.JoinFullName(account.FirstName, account.LastName);
        },
        cancellationToken);

        // No before, no after. The only thing that changed is a password hash, and that has no
        // business in an audit payload; actor, target and time are the whole record.
        await WriteMemberAuditAsync(
            caller,
            type,
            tenantCode,
            IamAuditActions.MemberPasswordReset,
            targetUserId,
            before: null,
            after: null,
            cancellationToken);

        var emailSent = await credentialEmails.SendPasswordResetAsync(
            targetUserId, email, displayName, newPassword, cancellationToken);

        await tokenVersions.InvalidateAsync(targetUserId, cancellationToken);

        return new ResetMemberPasswordResponse { UserId = targetUserId, EmailSent = emailSent };
    }

    // ---------------------------------------------------------------------------- guards

    /// <summary>
    /// Validates a tenant reference.
    /// <para>
    /// The code check is a <b>security guard</b>, not input hygiene. <c>*</c> is the tenant code of
    /// a whole-dimension member row, and the member write paths find their row by
    /// (user, tenant type, tenant code): without this, a global operator calling
    /// <c>/tenants/company/*/members/...</c> would land on somebody's whole-dimension row and
    /// rewrite the role set that governs <i>every</i> company for them - going around the one
    /// endpoint that is supposed to own that write. The administrator check does not catch it
    /// either, because for the code <c>*</c> its lookup key is exactly the whole-dimension key.
    /// On the create path the same hole mints a ghost member with a literal <c>*</c> code that then
    /// leaks into the data-scope envelope.
    /// </para>
    /// </summary>
    private static string NormalizeTenantRef(string tenantType, string tenantCode)
    {
        if (!TenantTypes.IsKnown(tenantType))
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest, "The tenant type must be either company or supplier.");
        }

        if (string.IsNullOrWhiteSpace(tenantCode) || tenantCode == TenantScopes.ScopeAllSentinelCode)
        {
            throw new BadRequestException(ErrorCodes.BadRequest, "The tenant code is not valid.");
        }

        return tenantType;
    }

    /// <summary>
    /// Whether the caller's active context reaches this tenant at all. The permission code is
    /// checked at the route; this closes the cross-tenant hole underneath it.
    /// <para>
    /// A platform context reaches everything. A global context reaches its own dimension only -
    /// choosing "all suppliers" at sign-in is an isolation decision, and honouring it here is what
    /// stops that session from acting on companies. A tenant context reaches exactly the tenant it
    /// is bound to: a company administrator manages a supplier from the supplier's own context, or
    /// from a global one, and standing elsewhere does not widen this.
    /// </para>
    /// </summary>
    private static void AuthorizeTenantAccess(BackOfficeCaller caller, string tenantType, string tenantCode)
    {
        var act = caller.Act
                  ?? throw new ForbiddenException(
                      ErrorCodes.TenantNotAuthorized, "The session has no active tenant context.");

        var allowed = act.Type switch
        {
            ActTypes.Platform => true,

            // An empty dimension is a token minted before dimension selection existed; it keeps
            // its old both-dimensions behaviour until it expires rather than dying mid-session.
            ActTypes.Global => act.Dimension.Length == 0 || act.Dimension == tenantType,
            ActTypes.Company => tenantType == TenantTypes.Company && act.Code == tenantCode,
            ActTypes.Supplier => tenantType == TenantTypes.Supplier && act.Code == tenantCode,
            _ => false,
        };

        if (!allowed)
        {
            throw new ForbiddenException(
                ErrorCodes.TenantNotAuthorized, "The caller may not manage this tenant.");
        }
    }

    private async Task AssertCanManageMembersAsync(
        BackOfficeCaller caller, string tenantType, string tenantCode, CancellationToken cancellationToken)
    {
        if (!await standing.CanManageMembersAsync(
                caller.RequireUserId(), tenantType, tenantCode, cancellationToken))
        {
            throw new ForbiddenException(
                ErrorCodes.CallerNotAdmin,
                "Only an administrator of this tenant may manage its members.");
        }
    }

    private async Task AssertCanReadTenantRosterAsync(
        BackOfficeCaller caller, string tenantType, string tenantCode, CancellationToken cancellationToken)
    {
        AuthorizeTenantAccess(caller, tenantType, tenantCode);

        var actTenant = caller.TenantRef();
        if (actTenant is { } tenant && tenant.TenantType == tenantType && tenant.TenantCode == tenantCode)
        {
            return;
        }

        await AssertCanManageMembersAsync(caller, tenantType, tenantCode, cancellationToken);
    }

    private static void ValidateTargetSelector(CreateMemberRequest request)
    {
        var hasUserId = request.UserId > 0;
        var hasNewUser = request.NewUser is not null && request.NewUser.Email.Length > 0;

        if (hasUserId == hasNewUser)
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest, "Exactly one of userId or newUser is required.");
        }

        // All four fields, not just the address. An administrator is opening an account on somebody
        // else's behalf and the system is about to mail that person a generated password: the
        // address has to be right, and the message has to be able to address them by name.
        if (hasNewUser
            && (string.IsNullOrWhiteSpace(request.NewUser!.Nickname)
                || string.IsNullOrWhiteSpace(request.NewUser.FirstName)
                || string.IsNullOrWhiteSpace(request.NewUser.LastName)))
        {
            throw new BadRequestException(
                ErrorCodes.ValidationFailed,
                "newUser requires email, nickname, firstName and lastName.");
        }
    }

    private async Task<TenantMember> FindManageableMemberAsync(
        int targetUserId, string tenantType, string tenantCode, CancellationToken cancellationToken)
    {
        var member = await members.FindByUserAndTenantAsync(
            targetUserId, tenantType, tenantCode, cancellationToken);

        return member is null || member.Status == TenantMemberStatuses.Removed
            ? throw new NotFoundException(
                ErrorCodes.MemberNotFound, "This user is not a member of this tenant.")
            : member;
    }

    /// <summary>
    /// One administrator may not rewrite another's membership - or their own - from inside a
    /// tenant context. Seats and their roles move through the explicit transfer flow only, and the
    /// error code is how the UI knows to offer it.
    /// <para>
    /// Global callers are exempt on purpose: the super administrator and whole-dimension operators
    /// work from the global directory, and the last-administrator guard is what protects the
    /// tenant from them.
    /// </para>
    /// </summary>
    private static void AssertAdminMemberNotPeerWritable(BackOfficeCaller caller, TenantMember member)
    {
        if (member.IsAdmin && caller.TenantRef() is not null)
        {
            throw new ConflictException(
                ErrorCodes.AdminTransferRequired,
                "An administrator's membership may only change through an explicit admin transfer.");
        }
    }

    /// <summary>
    /// Refuses a write that would leave the tenant with no administrator.
    /// <para>
    /// The super administrator short-circuits <b>before</b> the count. The guard exists so a tenant
    /// cannot lock itself out of its own member management; a platform super administrator can
    /// manage any tenant without a member row at all and can appoint a new administrator whenever
    /// they like, so for them "the last one" is not a lock-out, and refusing would only obstruct a
    /// legitimate clean-up.
    /// </para>
    /// </summary>
    private async Task AssertNotLastAdminAsync(
        int callerUserId,
        TenantMember member,
        string tenantType,
        string tenantCode,
        string message,
        CancellationToken cancellationToken)
    {
        if (!member.IsAdmin)
        {
            return;
        }

        if (await standing.IsPlatformSuperAdminAsync(callerUserId, cancellationToken))
        {
            return;
        }

        // More than one administrator means removing this one is not a lock-out.
        if (await members.CountActiveAdminsAsync(tenantType, tenantCode, cancellationToken) > 1)
        {
            return;
        }

        throw new ConflictException(ErrorCodes.AdminTransferRequired, message);
    }

    private async Task AssertNotSuperAdminTargetAsync(int targetUserId, CancellationToken cancellationToken)
    {
        var account = await accounts.FindAsync(targetUserId, cancellationToken)
                      ?? throw new BadRequestException(
                          ErrorCodes.MemberNotFound, "The target user does not exist.");

        if (account.IsSuperAdmin)
        {
            // 409 rather than 400: nothing about the request is malformed, it conflicts with what
            // that account currently is.
            throw new ConflictException(
                ErrorCodes.SuperAdminExclusive,
                "The platform super administrator cannot hold tenant roles or company or supplier access.");
        }
    }

    // ------------------------------------------------------------------- roles and ceiling

    private async Task AssertRolesFitTenantTypeAsync(
        string tenantType, IReadOnlyList<int> roleIds, CancellationToken cancellationToken)
    {
        if (roleIds.Count == 0)
        {
            return;
        }

        var mismatched = (await roles.FindByIdsAsync(roleIds, cancellationToken))
            .Where(role => !TenantRoleRules.CategoryBindableTo(role.Category, tenantType))
            .Select(role => role.Code)
            .Order(StringComparer.Ordinal)
            .ToList();

        if (mismatched.Count > 0)
        {
            throw new BadRequestException(
                ErrorCodes.RoleCategoryMismatch,
                $"These roles are not categorised for a {tenantType} tenant: {string.Join(", ", mismatched)}.");
        }
    }

    /// <summary>
    /// The caller's ceiling for this tenant, unioned with their whole-dimension ceiling.
    /// <para>
    /// The union is not a widening. A whole-dimension administrator holds no member row in the
    /// target tenant, so asking only for the tenant code resolves an <b>empty</b> ceiling - they
    /// could add members but every non-empty role set was refused. Nobody else gains anything: a
    /// tenant administrator has no <c>*</c> row, and a super administrator's first lookup already
    /// answers "everything here". What it deliberately does not reach is a target tenant's own
    /// custom roles, which under-grants rather than over-grants.
    /// </para>
    /// </summary>
    private async Task<IReadOnlySet<int>> DelegableRoleSetAsync(
        int callerUserId, string tenantType, string tenantCode, CancellationToken cancellationToken)
    {
        var forTenant = await delegation.DelegableRoleIdsAsync(
            callerUserId, tenantType, tenantCode, cancellationToken);
        var forDimension = await delegation.DelegableRoleIdsAsync(
            callerUserId, tenantType, TenantScopes.ScopeAllSentinelCode, cancellationToken);

        var union = new HashSet<int>(forTenant);
        union.UnionWith(forDimension);
        return union;
    }

    private async Task AssertRolesDelegableAsync(
        IReadOnlySet<int> delegable, IReadOnlyList<int> roleIds, CancellationToken cancellationToken)
    {
        var outside = roleIds.Where(id => !delegable.Contains(id)).ToList();
        if (outside.Count == 0)
        {
            return;
        }

        var codes = await RoleCodesAsync(outside, cancellationToken);
        var named = codes is { Count: > 0 } ? string.Join(", ", codes) : string.Join(", ", outside);

        throw new ForbiddenException(
            ErrorCodes.RoleNotDelegable,
            $"These roles are outside your delegable range: {named}.");
    }

    /// <summary>
    /// The bindings an overwrite has to carry over untouched: everything above the caller's
    /// ceiling, plus anything the catalogue says is filed under the wrong category for this tenant.
    /// <para>
    /// The second half is what keeps the migration's uncategorised bindings alive. The UI does not
    /// offer such a role, so it is never in a submitted set, and without this it would vanish
    /// silently during an unrelated edit. It cannot be re-granted - the write path refuses it - so
    /// preserving it is the only way it survives until an administrator files the role properly.
    /// A role id the catalogue cannot resolve at all is a dangling binding and is not protected.
    /// </para>
    /// </summary>
    private async Task<IReadOnlyList<int>> RoleIdsOutsideCeilingAsync(
        IReadOnlyList<int> currentRoleIds,
        string tenantType,
        IReadOnlySet<int> delegable,
        CancellationToken cancellationToken)
    {
        if (currentRoleIds.Count == 0)
        {
            return [];
        }

        var byId = (await roles.FindByIdsAsync(currentRoleIds, cancellationToken))
            .ToDictionary(role => role.Id);

        return [.. currentRoleIds.Where(id =>
            !delegable.Contains(id)
            || (byId.TryGetValue(id, out var role)
                && !TenantRoleRules.CategoryBindableTo(role.Category, tenantType)))];
    }

    private async Task<bool> ContainsAdminRoleAsync(
        IReadOnlyList<int> roleIds, CancellationToken cancellationToken) =>
        roleIds.Count != 0
        && (await roles.FindByIdsAsync(roleIds, cancellationToken)).Any(role => role.IsAdmin);

    /// <summary>
    /// Keeps <c>is_admin</c> equal to "this member holds an administrator role" (G16).
    /// <para>
    /// It applies to <b>every</b> row, whole-dimension rows included. Forcing it false for those
    /// once contradicted their own data - the platform bootstrap row is a scope-all row with the
    /// flag set - and quietly demoted it on any resynchronisation. Nothing reads the flag as
    /// "administrator of tenant X" without also filtering by X, and the <c>*</c> sentinel matches
    /// no real tenant, so a global row can never satisfy a tenant's last-administrator check.
    /// </para>
    /// </summary>
    private async Task SyncMemberAdminFlagAsync(
        TenantMember member, IReadOnlyList<int> roleIds, string stamp, CancellationToken cancellationToken) =>
        await ApplyMemberAdminFlagAsync(
            member, await ContainsAdminRoleAsync(roleIds, cancellationToken), stamp, cancellationToken);

    private async Task ApplyMemberAdminFlagAsync(
        TenantMember member, bool isAdmin, string stamp, CancellationToken cancellationToken)
    {
        if (member.IsAdmin == isAdmin)
        {
            return;
        }

        member.IsAdmin = isAdmin;
        Touch(member, stamp);
        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    // -------------------------------------------------------------------------- membership

    /// <summary>
    /// Finds, revives or creates the membership row.
    /// <para>
    /// A revival deliberately keeps the department name the row already had: the request's value
    /// only takes effect on a row that is being created. And a REMOVED row is revived rather than
    /// replaced, because the unique key on (user, tenant type, tenant code) would refuse a second
    /// one anyway.
    /// </para>
    /// </summary>
    private async Task<(TenantMember Member, string PreviousStatus)> UpsertActiveMembershipAsync(
        int userId,
        string tenantType,
        string tenantCode,
        string deptName,
        string stamp,
        CancellationToken cancellationToken)
    {
        var existing = await members.FindByUserAndTenantAsync(
            userId, tenantType, tenantCode, cancellationToken);

        if (existing is not null)
        {
            if (existing.Status == TenantMemberStatuses.Active)
            {
                throw new ConflictException(
                    ErrorCodes.MemberAlreadyExists,
                    "This user is already an active member of this tenant.");
            }

            var previousStatus = existing.Status;
            existing.Status = TenantMemberStatuses.Active;
            Touch(existing, stamp);
            await unitOfWork.SaveChangesAsync(cancellationToken);

            return (existing, previousStatus);
        }

        var now = clock.UtcNow;
        var member = new TenantMember
        {
            UserId = userId,
            TenantType = tenantType,
            TenantCode = tenantCode,
            DeptName = deptName,
            Status = TenantMemberStatuses.Active,
            CreatedAt = now,
            UpdatedAt = now,
            CreatedBy = stamp,
            UpdatedBy = stamp,
        };

        members.Add(member);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return (member, string.Empty);
    }

    // ------------------------------------------------------------------------------ audit

    /// <summary>
    /// One audit row per write, best effort - and <b>after</b> the commit, never inside it.
    /// <para>
    /// The placement is the whole point of the promise. PostgreSQL aborts a transaction the moment
    /// any statement in it fails, so an audit insert that failed inside the transaction would take
    /// the commit down with it however carefully the exception was caught: the swallow would be a
    /// lie, and the caller would get an opaque "current transaction is aborted" for a write that
    /// was otherwise complete. Outside, the swallow means what it says - the audit explains writes,
    /// it does not veto them - at the cost of a row that can be missing if the process dies in the
    /// gap, which is the trade the audit contract already accepts.
    /// </para>
    /// <para>
    /// Cancellation is deliberately not caught: it is not an audit failure, and turning it into one
    /// would report success for work that was abandoned.
    /// </para>
    /// </summary>
    private async Task WriteMemberAuditAsync(
        BackOfficeCaller caller,
        string tenantType,
        string tenantCode,
        string action,
        int targetUserId,
        MemberAuditSnapshot? before,
        MemberAuditSnapshot? after,
        CancellationToken cancellationToken)
    {
        try
        {
            await auditLog.WriteAsync(
                new IamAuditEntry(
                    caller.UserId,
                    caller.ActorName,
                    tenantType,
                    tenantCode,
                    action,
                    IamAuditActions.MemberTarget,
                    targetUserId.ToString(CultureInfo.InvariantCulture),
                    before is null ? null : JsonSerializer.Serialize(before, AuditJson),
                    after is null ? null : JsonSerializer.Serialize(after, AuditJson)),
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(
                ex,
                "The {Action} audit row for user {TargetUserId} in {TenantType}/{TenantCode} could not be "
                + "written. The change itself is committed.",
                action,
                targetUserId,
                tenantType,
                tenantCode);
        }
    }

    /// <summary>
    /// Role <b>codes</b>, never ids. The catalogue is seeded by full rebuild, so ids are
    /// reassigned on every reseed and an audit row that recorded them becomes unreadable the moment
    /// it matters; codes survive.
    /// </summary>
    private async Task<IReadOnlyList<string>?> RoleCodesAsync(
        IReadOnlyList<int> roleIds, CancellationToken cancellationToken)
    {
        if (roleIds.Count == 0)
        {
            return null;
        }

        try
        {
            var codes = (await roles.FindByIdsAsync(roleIds, cancellationToken))
                .Select(role => role.Code)
                .Order(StringComparer.Ordinal)
                .ToList();

            return codes.Count == 0 ? null : codes;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Role codes for an audit payload could not be resolved.");
            return null;
        }
    }

    /// <summary>
    /// What an action touched, and nothing else.
    /// <para>
    /// <see cref="IsAdmin"/> is nullable rather than a plain bool for one reason: the value worth
    /// recording here is usually <c>false</c> - a member losing administrator standing - and a
    /// non-nullable bool would be omitted by the write-null rule exactly when it matters most.
    /// </para>
    /// </summary>
    private sealed record MemberAuditSnapshot
    {
        [JsonPropertyName("status")]
        public string? Status { get; init; }

        [JsonPropertyName("is_admin")]
        public bool? IsAdmin { get; init; }

        [JsonPropertyName("role_codes")]
        public IReadOnlyList<string>? RoleCodes { get; init; }

        [JsonPropertyName("dept_name")]
        public string? DeptName { get; init; }
    }

    // ----------------------------------------------------------------------------- helpers

    private static string MemberDisplayName(NewMemberAccountRequest newUser)
    {
        var nickname = newUser.Nickname.Trim();
        if (nickname.Length > 0)
        {
            return nickname;
        }

        var full = BackOfficeNames.JoinFullName(newUser.FirstName, newUser.LastName);
        return full.Length > 0 ? full : EmailLocalPart(newUser.Email);
    }

    private static string EmailLocalPart(string email)
    {
        var at = email.IndexOf('@', StringComparison.Ordinal);
        return (at < 0 ? email : email[..at]).Trim().ToLowerInvariant();
    }

    private static string Stamp(BackOfficeCaller caller) =>
        string.IsNullOrWhiteSpace(caller.ActorName)
            ? caller.UserId.ToString(CultureInfo.InvariantCulture)
            : caller.ActorName;

    private void Touch(TenantMember member, string stamp)
    {
        member.UpdatedAt = clock.UtcNow;
        member.UpdatedBy = stamp;
    }

    private static IReadOnlyList<int> Distinct(IReadOnlyList<int>? ids) =>
        ids is null ? [] : [.. ids.Distinct()];

    /// <summary>Order-preserving union: what was submitted first, then what had to be kept.</summary>
    private static IReadOnlyList<int> Union(IReadOnlyList<int> first, IReadOnlyList<int> second) =>
        [.. first.Concat(second).Distinct()];
}
