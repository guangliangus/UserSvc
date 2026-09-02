using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>
/// Which back-office accounts, memberships and grants one caller may look at.
/// <para>
/// Three filters live here, and they answer three <b>different</b> questions. Collapsing them is
/// tempting and wrong: the directory asks "whose administrator am I?", the detail read asks "is this
/// the row I am already looking at?", and the colleague picker asks "who do I work with?".
/// </para>
/// </summary>
public sealed class UserVisibilityService(
    AdminScopeService adminScopes,
    ITenantMemberDirectory members,
    IUserTenantRoleRepository bindings,
    IRoleRepository roles)
{
    /// <summary>
    /// The account directory's filter, or <c>null</c> for unrestricted - which only the platform
    /// super administrator ever gets.
    /// </summary>
    public async Task<UserVisibilityFilter?> ResolveUserVisibilityFilterAsync(
        IBackOfficeCaller caller,
        CancellationToken cancellationToken)
    {
        var scope = await adminScopes.ResolveAdminScopeAsync(caller, cancellationToken);
        if (scope.IsSuperAdmin)
        {
            return null;
        }

        var wholeDimensions = new List<string>();
        foreach (var tenantType in new[] { TenantTypes.Company, TenantTypes.Supplier })
        {
            var sentinelKey = RoleOwner.KeyFor(
                RoleOwnerTypes.ForTenantType(tenantType), IamConstants.ScopeAllSentinelCode);

            if (scope.AdminRoleByOwner.TryGetValue(sentinelKey, out var adminRoles) && adminRoles.Count > 0)
            {
                wholeDimensions.Add(tenantType);
            }
        }

        // AdminTenants, not Owners. Owners is the role-ownership axis and is narrowed by the acting
        // context; read visibility lists every tenant the caller administers, and the dimension lock
        // below trims that to the current side.
        var tenants = scope.AdminTenants
            .Where(owner => owner.OwnerType != RoleOwnerTypes.System)
            .Select(owner => new TenantRef(RoleOwnerTypes.ToTenantType(owner.OwnerType), owner.Code))
            .ToList();

        // Dimension lock: read visibility follows the dimension signed in as. Signing in as a
        // supplier shows the supplier side only; the same person's company-side authorization is
        // simply not visible from here. Same direction as the write path. A GLOBAL token with no
        // dimension is a pre-selection token and means both, so it does not lock.
        var dimension = CallerFacts.ActDimension(caller);
        if (dimension.Length > 0)
        {
            wholeDimensions.RemoveAll(tenantType => tenantType != dimension);
            tenants.RemoveAll(tenant => tenant.TenantType != dimension);
        }

        return new UserVisibilityFilter(wholeDimensions, tenants);
    }

    /// <summary>
    /// The single-account read filter: the directory filter, plus the tenant the caller is acting as.
    /// <para>
    /// The tenant member list authorises purely on the acting claim, not on administrator standing.
    /// Without this step the two contradict each other: somebody holding the member-read permission
    /// but no administrator role sees a name, an email and a set of roles in the list, and gets
    /// refused the moment they click it. A read that merely restates a row the caller is already
    /// looking at must not be stricter than the list that produced it.
    /// </para>
    /// </summary>
    public async Task<UserVisibilityFilter?> ResolveUserReadFilterAsync(
        IBackOfficeCaller caller,
        CancellationToken cancellationToken)
    {
        var filter = await ResolveUserVisibilityFilterAsync(caller, cancellationToken);
        if (filter is null)
        {
            return null;
        }

        var (actType, actCode) = CallerFacts.ActTenantRef(caller);
        if (actType.Length == 0 || actCode.Length == 0)
        {
            return filter;
        }

        return filter.Tenants.Any(tenant => tenant.TenantType == actType && tenant.TenantCode == actCode)
            ? filter
            : filter.WithTenant(new TenantRef(actType, actCode));
    }

    /// <summary>
    /// The colleague picker's filter, built from <b>membership</b> rather than administrator standing.
    /// <para>
    /// The people who actually use a colleague picker hold no administrator standing at all, so
    /// reusing the directory filter would hand them an empty dropdown on a required field. It is
    /// still a boundary: before it existed the picker searched every back-office account on the
    /// platform, which made it a cross-tenant address book for anyone who could reach the route.
    /// </para>
    /// <para>
    /// It uses the GLOBAL-only dimension reading, not the general one: a tenant session is already
    /// the narrower axis, and membership does not depend on the acting context.
    /// </para>
    /// </summary>
    public async Task<UserVisibilityFilter?> ResolvePeerVisibilityFilterAsync(
        IBackOfficeCaller caller,
        CancellationToken cancellationToken)
    {
        var userId = caller.UserId;
        if (userId <= 0)
        {
            return new UserVisibilityFilter([], []);
        }

        if (await adminScopes.IsPlatformSuperAdminAsync(userId, cancellationToken))
        {
            return null;
        }

        var memberships = await members.ListActiveByUserAsync(userId, cancellationToken);
        var actDimension = CallerFacts.GlobalActDimension(caller);

        var wholeDimensions = new List<string>();
        var tenants = new List<TenantRef>();

        foreach (var membership in memberships)
        {
            if (actDimension.Length > 0 && membership.TenantType != actDimension)
            {
                continue;
            }

            if (membership.ScopeAll)
            {
                if (!wholeDimensions.Contains(membership.TenantType))
                {
                    wholeDimensions.Add(membership.TenantType);
                }

                continue;
            }

            var tenant = new TenantRef(membership.TenantType, membership.TenantCode);
            if (!tenants.Contains(tenant))
            {
                tenants.Add(tenant);
            }
        }

        return new UserVisibilityFilter(wholeDimensions, tenants);
    }

    /// <summary>
    /// Whether the caller may open this account at all.
    /// <para>
    /// Deliberately accepts DISABLED memberships, unlike the write guards: the tenant member list
    /// shows non-removed rows with an "enable" button, and a member switched off inside this tenant is
    /// exactly the row an administrator wants to open. It also does not refuse a super-administrator
    /// target the way the write path does - reading a row the caller is already looking at carries
    /// none of that risk, and the membership filter still stops everything outside their tenants.
    /// </para>
    /// </summary>
    public async Task AssertCanReadUserAsync(
        IBackOfficeCaller caller,
        int targetUserId,
        CancellationToken cancellationToken)
    {
        var filter = await ResolveUserReadFilterAsync(caller, cancellationToken);
        if (filter is null)
        {
            return;
        }

        var memberships = await members.ListNonRemovedByUserAsync(targetUserId, cancellationToken);
        if (VisibleMemberships(filter, memberships).Count > 0)
        {
            return;
        }

        throw new BadRequestException(
            ErrorCodes.CallerNotAdmin,
            "The target account is not a member of a tenant you administer.");
    }

    /// <summary>
    /// Whether one membership row is visible through a filter. The in-memory mirror of the directory
    /// query's WHERE clause; the two must stay in step.
    /// <para>
    /// A whole-dimension administrator sees every row on that side, <b>including other
    /// whole-dimension rows</b>. An administrator of one specific tenant sees only their own tenant
    /// and never a whole-dimension row - "the administrator of company A" has no business learning
    /// that an account also holds "all companies".
    /// </para>
    /// </summary>
    public static bool MembershipVisibleTo(UserVisibilityFilter? filter, TenantMembershipRow membership)
    {
        if (filter is null)
        {
            return true;
        }

        if (filter.WholeDimensions.Contains(membership.TenantType))
        {
            return true;
        }

        if (membership.ScopeAll)
        {
            return false;
        }

        return filter.Tenants.Any(tenant =>
            tenant.TenantType == membership.TenantType && tenant.TenantCode == membership.TenantCode);
    }

    /// <summary>The rows of <paramref name="memberships"/> this filter admits.</summary>
    public static IReadOnlyList<TenantMembershipRow> VisibleMemberships(
        UserVisibilityFilter? filter,
        IReadOnlyList<TenantMembershipRow> memberships) =>
        [.. memberships.Where(membership => MembershipVisibleTo(filter, membership))];

    /// <summary>The target's active roles, narrowed a second time to the memberships this caller
    /// administers - an account can belong to tenants the caller does not, and those bindings are
    /// not theirs to read.</summary>
    public async Task<IReadOnlyList<Role>> VisibleActiveUserRolesAsync(
        int userId,
        UserVisibilityFilter? filter,
        CancellationToken cancellationToken)
    {
        var memberships = await members.ListActiveByUserAsync(userId, cancellationToken);
        var visible = VisibleMemberships(filter, memberships);
        if (visible.Count == 0)
        {
            return [];
        }

        var roleIdsByMember = await bindings.ListRoleIdsByMemberIdsAsync(
            [.. visible.Select(membership => membership.Id)], cancellationToken);

        var roleIds = CallerFacts.DedupeSort(roleIdsByMember.Values.SelectMany(ids => ids));
        return roleIds.Count == 0 ? [] : await roles.FindByIdsAsync(roleIds, cancellationToken);
    }

    /// <summary>
    /// The target's scope envelope as this caller may see it.
    /// <para>
    /// <b>Never used to mint a token.</b> Token issuance reads the unfiltered envelope, because that
    /// answer has to describe the account itself rather than whoever happens to be looking at it.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyDictionary<string, ScopeClaim>> VisibleUserScopeClaimsAsync(
        int userId,
        UserVisibilityFilter? filter,
        ScopeEnvelopeService envelopes,
        CancellationToken cancellationToken)
    {
        if (filter is null)
        {
            return await envelopes.LoadUserScopeClaimsAsync(userId, cancellationToken);
        }

        if (await adminScopes.IsPlatformSuperAdminAsync(userId, cancellationToken))
        {
            return ScopeEnvelopeService.AllGlobal();
        }

        var memberships = await members.ListActiveByUserAsync(userId, cancellationToken);
        return ScopeEnvelopeService.Aggregate(userId, VisibleMemberships(filter, memberships));
    }
}

/// <summary>
/// Which back-office accounts a caller may see.
/// <para>
/// <c>null</c> means unrestricted. A non-null filter with both lists empty matches <b>nothing</b> -
/// it is not a widening. Any query built from it must short-circuit to an empty result rather than
/// omit its WHERE clause, which would silently turn the strictest filter into no filter at all.
/// </para>
/// </summary>
/// <param name="WholeDimensions">Tenant types the caller administers wholesale: every active member
/// on that side is visible.</param>
/// <param name="Tenants">The specific tenants the caller administers.</param>
public sealed record UserVisibilityFilter(
    IReadOnlyList<string> WholeDimensions,
    IReadOnlyList<TenantRef> Tenants)
{
    /// <summary>A copy with one more tenant admitted.</summary>
    public UserVisibilityFilter WithTenant(TenantRef tenant) =>
        this with { Tenants = [.. Tenants, tenant] };
}

/// <summary>One tenant, named.</summary>
public sealed record TenantRef(string TenantType, string TenantCode);
