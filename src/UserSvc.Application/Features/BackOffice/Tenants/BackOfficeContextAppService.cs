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
    /// </summary>
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
    /// end's current state alone; an empty list means "you have none" and closes every gate. A
    /// transient snapshot failure must produce the first.
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
            return response with
            {
                Roles = [],
                Permissions = [],
                Menus = [],
                MenuRoutes = [],
                Scopes = TenantContextResult.EmptyScopeEnvelope(),
            };
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
            TenantMasterDataEntry? entry = null;
            if (byKey is not null
                && !byKey.TryGetValue((member.TenantType, member.TenantCode), out entry))
            {
                entry = null;
            }

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
