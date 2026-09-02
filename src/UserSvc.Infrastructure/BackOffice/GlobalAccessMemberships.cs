using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// The two platform-level membership mutations role management owns the rules for, written against
/// the tenant slice's own repositories.
/// <para>
/// It is an adapter rather than a repository: the authority check, the role validation and the
/// audit row all stay in <c>SuperAdminAppService</c>, and every method here runs inside a
/// transaction that service opened. Nothing below commits - the caller's unit of work does - but
/// each step flushes, because the next step reads the row the previous one wrote.
/// </para>
/// <para>
/// <b>Advisory locks are taken in tenant-code order</b>, matching every other member write, so a
/// whole-dimension grant running beside an ordinary member change cannot deadlock with it.
/// </para>
/// </summary>
public sealed class GlobalAccessMemberships(
    ITenantMemberRepository members,
    IUserTenantRoleRepository bindings,
    IRoleRepository roles,
    IUnitOfWork unitOfWork,
    IClock clock) : IGlobalAccessMemberships
{
    private const string SystemActor = "system";

    public async Task GrantWholeDimensionAsync(
        int userId,
        string tenantType,
        IReadOnlyCollection<int> roleIds,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        var wanted = roleIds.Distinct().Order().ToList();

        var member = await members.FindByUserAndTenantForUpdateAsync(
            userId, tenantType, TenantScopes.ScopeAllSentinelCode, cancellationToken);

        if (member is null)
        {
            member = new TenantMember
            {
                UserId = userId,
                TenantType = tenantType,
                TenantCode = TenantScopes.ScopeAllSentinelCode,
                ScopeAll = true,
                Status = TenantMemberStatuses.Active,
                CreatedAt = now,
                UpdatedAt = now,
                CreatedBy = SystemActor,
                UpdatedBy = SystemActor,
            };

            members.Add(member);
        }
        else
        {
            // A revoked whole-dimension row is revived rather than replaced: the unique key on
            // (user_id, tenant_type, tenant_code) would refuse a second one, and reviving keeps the
            // audit trail pointing at one continuous row.
            member.Status = TenantMemberStatuses.Active;
            member.ScopeAll = true;
            Touch(member, now);
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);

        await bindings.ReplaceForMemberAsync(member.Id, wanted, SystemActor, now, cancellationToken);

        // The flag is derived from the bindings on every row, whole-dimension rows included: this
        // one grants breadth over a dimension, and if one of the roles it carries is an
        // administrator role then it administers as well.
        member.IsAdmin = await AnyAdminRoleAsync(wanted, cancellationToken);
        Touch(member, now);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        await RetireSpecificMembershipsAsync(userId, tenantType, now, cancellationToken);
    }

    /// <summary>
    /// Takes the breadth away and leaves everything else alone. Specific memberships are
    /// deliberately untouched: they were retired when the whole-dimension row was granted, and
    /// anything created since is somebody's later decision, not this one's to undo.
    /// </summary>
    public async Task RevokeWholeDimensionAsync(
        int userId, string tenantType, CancellationToken cancellationToken)
    {
        var member = await members.FindByUserAndTenantForUpdateAsync(
            userId, tenantType, TenantScopes.ScopeAllSentinelCode, cancellationToken);

        if (member is null)
        {
            return;
        }

        await ClearAndRetireAsync(member, clock.UtcNow, cancellationToken);
    }

    /// <summary>
    /// Strips every membership from an account being promoted, and reports what was taken.
    /// <para>
    /// The role codes are read <b>before</b> the bindings are replaced, because after that there is
    /// nothing left to read and the audit row's whole job is to say what the promotion took away.
    /// The last-administrator guard does not run: leaving a tenant without one here is the super
    /// administrator's own explicit decision.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<ClearedMembership>> ClearAllMembershipsAsync(
        int userId, CancellationToken cancellationToken)
    {
        var held = await members.ListNonRemovedByUserIdsAsync([userId], cancellationToken);
        if (held.Count == 0)
        {
            return [];
        }

        var ordered = held
            .OrderBy(member => member.TenantType, StringComparer.Ordinal)
            .ThenBy(member => member.TenantCode, StringComparer.Ordinal)
            .ToList();

        // Every lock first, in one pass and in a fixed order, before any row is touched. Taking
        // them as we go would interleave lock acquisition with writes and reintroduce the ordering
        // hazard the sort exists to remove.
        foreach (var member in ordered)
        {
            await members.AcquireTenantLockAsync(member.TenantType, member.TenantCode, cancellationToken);
        }

        var now = clock.UtcNow;
        var cleared = new List<ClearedMembership>(ordered.Count);

        foreach (var member in ordered)
        {
            var roleCodes = await RoleCodesOfAsync(member.Id, cancellationToken);
            var wasAdmin = member.IsAdmin;

            await ClearAndRetireAsync(member, now, cancellationToken);

            cleared.Add(new ClearedMembership(
                member.TenantType, member.TenantCode, member.ScopeAll, wasAdmin, roleCodes));
        }

        return cleared;
    }

    /// <summary>
    /// Within-dimension exclusivity: holding "every company" and company C001 at once makes the
    /// narrower row unreadable, and it would silently come back into force the day the wider one is
    /// revoked. Across dimensions the two are independent, so this only ever touches one.
    /// </summary>
    private async Task RetireSpecificMembershipsAsync(
        int userId, string tenantType, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var held = await members.ListNonRemovedByUserIdsAsync([userId], cancellationToken);

        var specific = held
            .Where(member => member.TenantType == tenantType && !member.ScopeAll)
            .Where(member => member.TenantCode != TenantScopes.ScopeAllSentinelCode)
            .OrderBy(member => member.TenantCode, StringComparer.Ordinal)
            .ToList();

        foreach (var member in specific)
        {
            await members.AcquireTenantLockAsync(member.TenantType, member.TenantCode, cancellationToken);
            await ClearAndRetireAsync(member, now, cancellationToken);
        }
    }

    private async Task ClearAndRetireAsync(
        TenantMember member, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await bindings.ReplaceForMemberAsync(member.Id, [], SystemActor, now, cancellationToken);

        member.IsAdmin = false;
        member.Status = TenantMemberStatuses.Removed;
        Touch(member, now);

        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    private async Task<IReadOnlyList<string>> RoleCodesOfAsync(int memberId, CancellationToken cancellationToken)
    {
        var bound = await bindings.ListByMemberIdAsync(memberId, cancellationToken);
        if (bound.Count == 0)
        {
            return [];
        }

        var found = await roles.FindByIdsAsync(
            [.. bound.Select(binding => binding.RoleId).Distinct()], cancellationToken);

        return [.. found.Select(role => role.Code).Order(StringComparer.Ordinal)];
    }

    private async Task<bool> AnyAdminRoleAsync(
        IReadOnlyCollection<int> roleIds, CancellationToken cancellationToken) =>
        roleIds.Count != 0
        && (await roles.FindByIdsAsync(roleIds, cancellationToken)).Any(role => role.IsAdmin);

    private static void Touch(TenantMember member, DateTimeOffset now)
    {
        member.UpdatedAt = now;
        member.UpdatedBy = SystemActor;
    }
}
