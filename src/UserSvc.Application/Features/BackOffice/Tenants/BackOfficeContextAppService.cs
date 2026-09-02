using System.Globalization;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Features.BackOffice.Tenants;

/// <summary>
/// The endpoints the back-office shell talks to: which contexts may I enter, put me in one, and
/// what does my session currently look like.
/// <para>
/// It does no token minting. In this service tokens come out of the OpenIddict token endpoint, so
/// choosing a context is a decision - validated, audited, and answered with the authority surface
/// that decision produces - and the credential that carries it is issued separately. Keeping the
/// two apart also keeps this service honest: the surface in the response body is recomputed every
/// time, and cannot go stale inside a token the way an embedded copy would.
/// </para>
/// </summary>
public sealed class BackOfficeContextAppService(
    TenantContextAppService context,
    ITenantMemberRepository members,
    IBackOfficeAccountDirectory accounts,
    ITenantMasterDataDirectory masterData,
    IIamAuditLog auditLog,
    IClock clock,
    ILogger<BackOfficeContextAppService> logger,
    IAuthzSnapshotProvider? snapshots = null)
{
    /// <summary>
    /// The contexts this session may choose from. Accepts a token that has not chosen one yet -
    /// that is the whole point of it.
    /// </summary>
    public async Task<TenantListResponse> ListTenantsAsync(
        BackOfficeCaller caller, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);

        var userId = caller.RequireUserId();

        var isGlobal = await context.IsGlobalUserAsync(userId, cancellationToken);
        var dimensions = await context.GlobalDimensionsAsync(userId, cancellationToken);
        var memberships = await members.ListActiveByUserAsync(userId, cancellationToken);

        return new TenantListResponse
        {
            // The mounted company of a supplier context comes out of the data-scope envelope,
            // which this endpoint does not compute; the shell already has it from the context
            // response that put the session here.
            ActiveTenant = ActiveTenantFrom(caller.Act, scopes: null),
            IsGlobal = isGlobal,
            Tenants = await BuildTenantSummariesAsync(dimensions, memberships, cancellationToken),
        };
    }

    /// <summary>
    /// Enter a context.
    /// <para>
    /// The order of the checks is deliberate and the master-data check is deliberately last: it is
    /// the only one that leaves the process, and a request already refused for a local reason
    /// should not pay for it.
    /// </para>
    /// <para>
    /// <b>A tenant this caller does not hold answers 403, not 400.</b> That is a ratified
    /// deviation from porting spec 09 section 3.3, whose steps 2 to 4 say "BadRequest". In the
    /// service being replaced that word named an error <i>kind</i>, not a status: every soft error
    /// it constructed - BadRequest and Conflict alike - went out as HTTP 200 with
    /// <c>success=false</c> (same spec, section 4). There is therefore no 400 on the wire to
    /// preserve. The port has to pick a real status for the kind, exactly as it already does for
    /// TENANT_DISABLED (403) and TENANT_INACTIVE (409).
    /// </para>
    /// <para>
    /// 403 for three reasons. Nothing about the request is malformed: the caller is authenticated,
    /// the token is valid, <c>tenantType</c> is one of the two legal values and <c>tenantCode</c>
    /// is a well-formed code. What is missing is a member row - "understood the request, refuses
    /// to authorize it", which is what 403 is for. The status classes are grouped by what the
    /// client should do next, and for <i>this</i> tenant the answer is never "correct the field and
    /// resubmit" but "stop asking about this one"; the client's real recovery is the switcher list,
    /// which is a different request rather than a corrected one. And TENANT_NOT_AUTHORIZED already
    /// means 403 everywhere else in this service - the per-request permission gate answers exactly
    /// that for a forged or stale <c>act</c> - so answering 400 here would hand the front end two
    /// status branches for one error code, and the error code is the part clients are promised.
    /// </para>
    /// </summary>
    /// <exception cref="BadRequestException">The tenant type is neither company nor supplier. This
    /// one is genuinely a malformed field, which is why it keeps the 400.</exception>
    /// <exception cref="ForbiddenException">TENANT_NOT_AUTHORIZED when no member row backs the
    /// request, or TENANT_DISABLED when the membership is suspended.</exception>
    /// <exception cref="UnauthorizedException">ACCOUNT_DISABLED - the account itself is switched
    /// off, so the answer is to re-authenticate rather than to pick elsewhere.</exception>
    /// <exception cref="ConflictException">TENANT_INACTIVE - the tenant is switched off in the
    /// master data, a platform-side state that can be flipped back.</exception>
    public async Task<TenantContextResponse> SelectContextAsync(
        BackOfficeCaller caller, SelectTenantContextRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(request);

        var userId = caller.RequireUserId();

        if (!TenantTypes.IsKnown(request.TenantType))
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest, "The tenant type must be either company or supplier.");
        }

        // A whole dimension is its own kind of context, authorized by standing rather than by a
        // member row - the super administrator has no rows at all - so it branches before any
        // membership lookup.
        if (request.TenantCode == TenantScopes.ScopeAllSentinelCode)
        {
            return await SelectGlobalDimensionAsync(userId, request.TenantType, cancellationToken);
        }

        var member = await members.FindByUserAndTenantAsync(
                         userId, request.TenantType, request.TenantCode, cancellationToken)
                     ?? throw new ForbiddenException(
                         ErrorCodes.TenantNotAuthorized, "This account is not a member of this tenant.");

        // Defensive: a whole-dimension row is reached through the branch above, and a literal code
        // should never match one. It keeps the sentinel out of the tenant derivation, which would
        // happily treat "*" as a real tenant code.
        if (member.ScopeAll)
        {
            throw new ForbiddenException(
                ErrorCodes.TenantNotAuthorized, "A whole-dimension membership is not a selectable tenant.");
        }

        if (member.Status == TenantMemberStatuses.Disabled)
        {
            throw new ForbiddenException(ErrorCodes.TenantDisabled, "This membership is disabled.");
        }

        if (member.Status != TenantMemberStatuses.Active)
        {
            throw new ForbiddenException(ErrorCodes.TenantNotAuthorized, "This membership is not active.");
        }

        // A member row says nothing about the account. Every other path that issues credentials
        // refuses a disabled account, and without the same refusal here somebody whose account was
        // switched off but whose membership was left alone could keep re-entering contexts.
        var account = await RequireEnabledAccountAsync(userId, cancellationToken);

        if (!await TenantIsUsableAsync(request.TenantType, request.TenantCode, cancellationToken))
        {
            throw new ConflictException(
                ErrorCodes.TenantInactive, "This tenant is inactive or has not been approved.");
        }

        var result = await context.ComputeAsync(
            userId,
            new ActClaim(ActTypes.ForTenantType(request.TenantType), request.TenantCode),
            cancellationToken);

        await AuditTenantSwitchAsync(
            account, request.TenantType, request.TenantCode, cancellationToken);
        await TouchLastLoginAsync(userId, cancellationToken);

        return ToContextResponse(result);
    }

    /// <summary>
    /// Enter a whole dimension.
    /// <para>
    /// Two differences from the tenant path, both of them intentional. There is no master-data
    /// check, because a dimension is not a tenant and cannot be switched off. And the administrator
    /// flag is always false: a dimension has no administrator seat - that standing lives on the
    /// whole-dimension member row and travels as permissions.
    /// </para>
    /// <para>
    /// A dimension this account does not hold is refused with 403 for the same reason a tenant is;
    /// see <see cref="SelectContextAsync"/>.
    /// </para>
    /// </summary>
    private async Task<TenantContextResponse> SelectGlobalDimensionAsync(
        int userId, string dimension, CancellationToken cancellationToken)
    {
        var dimensions = await context.GlobalDimensionsAsync(userId, cancellationToken);
        if (!dimensions.Contains(dimension, StringComparer.Ordinal))
        {
            throw new ForbiddenException(
                ErrorCodes.TenantNotAuthorized,
                "This account holds no whole-dimension access on that dimension.");
        }

        var account = await RequireEnabledAccountAsync(userId, cancellationToken);

        var result = await context.ComputeAsync(
            userId, new ActClaim(ActTypes.Global, Dimension: dimension), cancellationToken);

        // Audited with the dimension and the sentinel, so the trail says which side was entered
        // rather than filing it anonymously under the platform.
        await AuditTenantSwitchAsync(
            account, dimension, TenantScopes.ScopeAllSentinelCode, cancellationToken);
        await TouchLastLoginAsync(userId, cancellationToken);

        return ToContextResponse(result);
    }

    /// <summary>
    /// Everything the shell needs to draw itself.
    /// <para>
    /// Deliberately carries <b>no permission requirement</b> - see the endpoint for why - and its
    /// authority fields are three-state. Null means "not delivered this time" and leaves the front
    /// end's current state alone; an empty list means "you have none" and closes every gate.
    /// </para>
    /// <para>
    /// Which means <b>the two ways of having nothing must not be answered the same way</b>, and
    /// telling them apart is what the two catch clauses below are for. A snapshot that refuses
    /// with 403 has decided something definite about this caller - not a member of this tenant,
    /// membership no longer active, no longer the platform super administrator - and the shell has
    /// to <i>clear</i>: this endpoint is its resynchronisation source, and answering null there
    /// tells it to keep the sidebar of a tenant the account has been removed from. A snapshot that
    /// could not be read at all has decided nothing, and answering empty there would report a
    /// Redis or database wobble to the user as "your permissions were revoked".
    /// </para>
    /// <para>
    /// The status class is the discriminator, and it is the right one rather than a convenient one:
    /// 403 is defined in this service as "stop trying, nothing about the request can be corrected",
    /// so every 403 the derivation funnel raises is by construction a definite answer, while an
    /// outage arrives as a 502, as an infrastructure exception, or as this component not being
    /// wired up at all. Catching the exception type instead of inspecting error codes also keeps
    /// this call site honest as the funnel grows: a new definite refusal is a 403 and lands in the
    /// clearing branch without anybody having to remember to extend a list of codes.
    /// </para>
    /// <para>
    /// <see cref="BackOfficeMeResponse.ActiveTenant"/> survives a refusal on purpose. It is a fact
    /// about the presented token, not a grant, and the shell needs it to say <i>which</i> context
    /// it has just lost - next to a <see cref="BackOfficeMeResponse.Tenants"/> list that no longer
    /// contains it, which is the switcher the user is meant to pick from instead.
    /// </para>
    /// </summary>
    public async Task<BackOfficeMeResponse> GetMeAsync(
        BackOfficeCaller caller, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);

        var userId = caller.RequireUserId();
        var account = await accounts.FindAsync(userId, cancellationToken)
                      ?? throw new NotFoundException(
                          ErrorCodes.UserNotFound, "The back-office account was not found.");

        var isGlobal = await context.IsGlobalUserAsync(userId, cancellationToken);
        var dimensions = await context.GlobalDimensionsAsync(userId, cancellationToken);
        var memberships = await members.ListActiveByUserAsync(userId, cancellationToken);

        var act = caller.Act;
        var isTenantAdmin = act is not null
                            && act.Type is ActTypes.Company or ActTypes.Supplier
                            && memberships.Any(member =>
                                member.TenantType == ActTypes.ToTenantType(act.Type)
                                && member.TenantCode == act.Code
                                && member.IsAdmin);

        var response = new BackOfficeMeResponse
        {
            User = new BackOfficeUserResponse
            {
                Id = account.Id,
                FirstName = account.FirstName,
                LastName = account.LastName,
                Nickname = BackOfficeNames.Display(account.FirstName, account.LastName, account.Nickname),
                StaffCode = account.StaffCode,
                Status = account.Status,
                LastLoginAt = account.LastLoginAt,
            },
            Origin = account.Origin,
            ActiveTenant = ActiveTenantFrom(act, scopes: null),
            IsTenantAdmin = isTenantAdmin,
            IsGlobal = isGlobal,
            Tenants = await BuildTenantSummariesAsync(dimensions, memberships, cancellationToken),
        };

        // No context, or a context type this build does not know: an explicit empty surface, the
        // same shape a no-access sign-in produces. The front end reads it and closes the gates.
        if (act is null || !ActTypes.IsKnown(act.Type))
        {
            return WithNoAuthority(response);
        }

        if (snapshots is null)
        {
            // The snapshot component is not wired up in this deployment. Undelivered, not empty.
            return response;
        }

        try
        {
            var snapshot = await snapshots.GetOrComputeAsync(
                userId, act, account.TokenVersion, cancellationToken);
            var routes = await snapshots.MenuRoutesForCodesAsync(snapshot.Menus, cancellationToken);

            return response with
            {
                Roles = snapshot.Roles,
                Permissions = snapshot.Permissions,
                Menus = snapshot.Menus,
                Scopes = snapshot.Scopes,
                MenuRoutes = routes,

                // Recomputed from the snapshot: a supplier context's mounted company is only
                // knowable from the data-scope envelope, and the envelope only exists here.
                ActiveTenant = ActiveTenantFrom(act, snapshot.Scopes),
            };
        }
        catch (ForbiddenException ex)
        {
            // A definite "you hold nothing here", not an outage: the account is not a member of
            // this tenant, its membership is no longer active, or it no longer carries the
            // platform flag. Reported as an explicit empty surface - the same shape a no-access
            // sign-in produces - because null would tell the shell to keep rendering the tenant it
            // has just been removed from. Information, not warning: this is a normal answer to a
            // stale token, and the gated routes refuse it in the same breath.
            logger.LogInformation(
                ex,
                "The authorization snapshot refused context {ActType} for user {UserId}; the shell "
                + "response states its grants as empty so the shell clears.",
                act.Type,
                userId);

            return WithNoAuthority(response);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(
                ex,
                "The authorization snapshot for user {UserId} could not be read; the shell response "
                + "reports its grants as undelivered rather than as empty.",
                userId);

            return response;
        }
    }

    /// <summary>
    /// The shell response with every authority field stated as empty: "you have none", which closes
    /// every gate. The counterpart of leaving them null, which means "not delivered".
    /// </summary>
    private static BackOfficeMeResponse WithNoAuthority(BackOfficeMeResponse response) =>
        response with
        {
            Roles = [],
            Permissions = [],
            Menus = [],
            MenuRoutes = [],
            Scopes = TenantContextResult.EmptyScopeEnvelope(),
        };

    // ---------------------------------------------------------------------------- helpers

    private async Task<BackOfficeAccount> RequireEnabledAccountAsync(
        int userId, CancellationToken cancellationToken)
    {
        var account = await accounts.FindAsync(userId, cancellationToken)
                      ?? throw new NotFoundException(
                          ErrorCodes.UserNotFound, "The back-office account was not found.");

        return account.Status == BackOfficeAccountStates.Disabled
            ? throw new UnauthorizedException(ErrorCodes.AccountDisabled, "This account is disabled.")
            : account;
    }

    /// <summary>
    /// Whether the master data still considers this tenant a place anyone may enter.
    /// <para>
    /// <b>Fails open.</b> Sign-in and context switching cannot stop platform-wide because the
    /// master data is unreachable, and this is not the authorization boundary - that is the member
    /// row plus the permission codes. It keeps people out of a tenant that has been switched off,
    /// and nothing more.
    /// </para>
    /// </summary>
    private async Task<bool> TenantIsUsableAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken)
    {
        var companyCodes = tenantType == TenantTypes.Company ? new[] { tenantCode } : [];
        var supplierCodes = tenantType == TenantTypes.Supplier ? new[] { tenantCode } : [];

        var entries = await masterData.ValidateAsync(companyCodes, supplierCodes, cancellationToken);
        if (entries is null)
        {
            logger.LogWarning(
                "The tenant master data could not be reached; entry into {TenantType}/{TenantCode} was "
                + "allowed without it.",
                tenantType,
                tenantCode);

            return true;
        }

        var entry = entries.FirstOrDefault(e =>
            e.TenantType == tenantType && e.TenantCode == tenantCode);

        // A code the answer left out is waved through, which is not the same reading the port
        // describes - it says an absent entry and an Unknown one mean the same thing, and the rule
        // being ported is "the row exists and its status is ACTIVE". Left as it is on purpose: the
        // same judgement decides the switcher list, that list feeds the sign-in option count in
        // another slice, and tightening one call site without the other produces entries the
        // select endpoint refuses. Unreachable today - the only adapter answers null wholesale -
        // and reported as a defect for whoever owns the port to settle in one move.
        return entry is null || entry.Usable;
    }

    /// <summary>
    /// The context switcher's entries: whole dimensions first, because the widest choice reads best
    /// at the top, then the tenants this person actually belongs to.
    /// <para>
    /// Tenants the master data calls unusable are dropped here, using the same judgement the select
    /// endpoint applies - listing an entry that the next call would refuse only produces dead rows.
    /// When the master data is unreachable everything stays, matching the fail-open direction used
    /// everywhere else in this file.
    /// </para>
    /// </summary>
    private async Task<IReadOnlyList<TenantSummaryResponse>> BuildTenantSummariesAsync(
        IReadOnlyList<string> globalDimensions,
        IReadOnlyList<TenantMember> memberships,
        CancellationToken cancellationToken)
    {
        var summaries = globalDimensions
            .Select(dimension => new TenantSummaryResponse
            {
                TenantType = dimension,
                TenantCode = TenantScopes.ScopeAllSentinelCode,
                ScopeAll = true,
            })
            .ToList();

        // Whole-dimension rows are excluded: that access is offered as the dimension entry above,
        // and offering it twice would look like two different places.
        var loginTenants = memberships
            .Where(member => member.Status == TenantMemberStatuses.Active)
            .Where(member => !member.ScopeAll)
            .Where(member => TenantTypes.IsKnown(member.TenantType))
            .ToList();

        if (loginTenants.Count == 0)
        {
            return summaries;
        }

        var entries = await masterData.ValidateAsync(
            [.. loginTenants.Where(m => m.TenantType == TenantTypes.Company).Select(m => m.TenantCode)],
            [.. loginTenants.Where(m => m.TenantType == TenantTypes.Supplier).Select(m => m.TenantCode)],
            cancellationToken);

        var byKey = entries?.ToDictionary(entry => (entry.TenantType, entry.TenantCode));

        foreach (var member in loginTenants)
        {
            var entry = byKey?.GetValueOrDefault((member.TenantType, member.TenantCode));

            // Only a verdict that came back and said "no" drops a tenant. A missing entry stays,
            // matching the select endpoint's reading of the same answer - see the note there.
            if (entry is { Usable: false })
            {
                continue;
            }

            summaries.Add(new TenantSummaryResponse
            {
                TenantType = member.TenantType,
                TenantCode = member.TenantCode,
                TenantName = entry?.Name,
                IsAdmin = member.IsAdmin,
                DeptName = member.DeptName ?? string.Empty,
            });
        }

        return summaries;
    }

    /// <summary>
    /// Where the session is acting, for the shell. Null when there is no context - which the shell
    /// renders as "nothing chosen yet", not as "everything".
    /// </summary>
    private static ActiveTenantResponse? ActiveTenantFrom(
        ActClaim? act, IReadOnlyDictionary<string, ScopeClaim>? scopes)
    {
        if (act is null)
        {
            return null;
        }

        var response = new ActiveTenantResponse
        {
            Type = act.Type.ToLowerInvariant(),
            Dimension = act.Dimension,
        };

        return act.Type switch
        {
            ActTypes.Company => response with { CompanyCode = act.Code },
            ActTypes.Supplier => response with
            {
                SupplierCode = act.Code,

                // The company a supplier hangs off is not in the act claim; it is derived, and the
                // envelope is where the derivation ended up.
                CompanyCode = scopes?.GetValueOrDefault(TenantTypes.Company, ScopeClaim.None)
                    .Values.FirstOrDefault() ?? string.Empty,
            },
            _ => response,
        };
    }

    private static TenantContextResponse ToContextResponse(TenantContextResult result) =>
        new()
        {
            ActiveTenant = ActiveTenantFrom(result.Act, result.Scopes),
            IsTenantAdmin = result.Act?.IsAdmin ?? false,
            Roles = result.Roles,
            Permissions = result.Permissions,
            Menus = result.Menus,
            Scopes = result.Scopes,
        };

    private async Task AuditTenantSwitchAsync(
        BackOfficeAccount account,
        string tenantType,
        string tenantCode,
        CancellationToken cancellationToken)
    {
        try
        {
            await auditLog.WriteAsync(
                new IamAuditEntry(
                    account.Id,
                    BackOfficeNames.Display(account.FirstName, account.LastName, account.Nickname),
                    tenantType,
                    tenantCode,
                    IamAuditActions.TenantSwitch,
                    IamAuditActions.MemberTarget,
                    account.Id.ToString(CultureInfo.InvariantCulture)),
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(
                ex, "The tenant-switch audit row for user {UserId} could not be written.", account.Id);
        }
    }

    private async Task TouchLastLoginAsync(int userId, CancellationToken cancellationToken)
    {
        try
        {
            await accounts.TouchLastLoginAsync(userId, clock.UtcNow, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "The last-login timestamp for user {UserId} could not be updated.", userId);
        }
    }
}
