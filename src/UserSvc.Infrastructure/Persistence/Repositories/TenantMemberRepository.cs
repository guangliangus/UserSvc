using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// EF Core adapter for tenant memberships.
/// <para>
/// Two invariants run through the whole file. Lookups by tenant code must never match a
/// whole-dimension row - its code column holds the literal <c>*</c> sentinel, and treating that as
/// a tenant code is how a global row starts answering for a tenant nobody asked about. And a
/// lookup by (user, tenant) returns rows in any status, because the caller needs the removed row
/// in order to revive it.
/// </para>
/// <para>
/// The two queries that reach tables this slice does not own - roles, role permissions,
/// permissions - use EF's own raw SQL rather than a second data-access stack, so they run on the
/// same connection inside the same transaction (decision 15).
/// </para>
/// </summary>
public sealed class TenantMemberRepository(UserSvcDbContext db) : ITenantMemberRepository
{
    public void Add(TenantMember member) => db.TenantMembers.Add(member);

    public Task<TenantMember?> FindByUserAndTenantAsync(
        int userId, string tenantType, string tenantCode, CancellationToken cancellationToken) =>
        db.TenantMembers.FirstOrDefaultAsync(
            member => member.UserId == userId
                      && member.TenantType == tenantType
                      && member.TenantCode == tenantCode,
            cancellationToken);

    /// <summary>
    /// The same row under a <c>FOR UPDATE</c> lock.
    /// <para>
    /// Written as raw SQL because EF has no row-lock hint. The column list is <c>*</c> and that is
    /// safe here only because this entity has no system-column properties mapped - had it kept an
    /// <c>xmin</c> concurrency token, that column would be missing from the result and the
    /// materializer would fail at runtime rather than at compile time.
    /// </para>
    /// </summary>
    public Task<TenantMember?> FindByUserAndTenantForUpdateAsync(
        int userId, string tenantType, string tenantCode, CancellationToken cancellationToken) =>
        db.TenantMembers
            .FromSql(
                $"""
                 SELECT * FROM iam.tenant_members
                 WHERE user_id = {userId} AND tenant_type = {tenantType} AND tenant_code = {tenantCode}
                 FOR UPDATE
                 """)
            .FirstOrDefaultAsync(cancellationToken);

    public Task<TenantMember?> FindAdminAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken) =>
        ActiveAdmins(tenantType, tenantCode).FirstOrDefaultAsync(cancellationToken);

    public async Task<IReadOnlyList<TenantMember>> FindAdminsAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken) =>
        await ActiveAdmins(tenantType, tenantCode).ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<TenantMember>> ListActiveByUserAsync(
        int userId, CancellationToken cancellationToken) =>
        await db.TenantMembers
            .Where(member => member.UserId == userId && member.Status == TenantMemberStatuses.Active)
            .OrderBy(member => member.Id)
            .ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<TenantMember>> ListNonRemovedByUserIdsAsync(
        IReadOnlyCollection<int> userIds, CancellationToken cancellationToken)
    {
        if (userIds.Count == 0)
        {
            return [];
        }

        var ids = userIds.ToArray();

        // DISABLED rows stay in: an administrator has to see a suspended membership to reinstate
        // it. REMOVED is the status that means gone.
        return await db.TenantMembers
            .Where(member => ids.Contains(member.UserId)
                             && member.Status != TenantMemberStatuses.Removed)
            .OrderBy(member => member.UserId)
            .ThenByDescending(member => member.IsAdmin)
            .ThenBy(member => member.Id)
            .ToListAsync(cancellationToken);
    }

    public async Task<TenantMemberPage> ListByTenantAsync(
        TenantMemberQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var rows = db.TenantMembers.Where(member =>
            member.TenantType == query.TenantType && member.TenantCode == query.TenantCode);

        rows = query.Status.Length == 0
            ? rows.Where(member => member.Status != TenantMemberStatuses.Removed)
            : rows.Where(member => member.Status == query.Status);

        // Null is "no keyword". An empty list is "the keyword matched nobody", and it has to
        // produce no rows rather than fall through to an unfiltered roster.
        if (query.UserIds is { } userIds)
        {
            var ids = userIds.ToArray();
            rows = rows.Where(member => ids.Contains(member.UserId));
        }

        var total = await rows.CountAsync(cancellationToken);

        var items = await rows
            .OrderByDescending(member => member.IsAdmin)
            .ThenBy(member => member.Id)
            .Skip((query.Page - 1) * query.PageSize)
            .Take(query.PageSize)
            .ToListAsync(cancellationToken);

        return new TenantMemberPage(items, total);
    }

    public Task<int> CountActiveAdminsAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken) =>
        ActiveAdmins(tenantType, tenantCode).CountAsync(cancellationToken);

    /// <summary>
    /// Serializes member writes for one tenant.
    /// <para>
    /// The lock is transaction-scoped, so this <b>must</b> run inside one: outside a transaction
    /// PostgreSQL takes and releases it within the statement, which looks exactly like working code
    /// until two administrators press the button at the same moment. It runs on the EF connection,
    /// which is what puts it in the caller's transaction.
    /// </para>
    /// </summary>
    public async Task AcquireTenantLockAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken)
    {
        var key = $"tenant:{tenantType}:{tenantCode}";
        await db.Database.ExecuteSqlAsync(
            $"SELECT pg_advisory_xact_lock(hashtext({key}))", cancellationToken);
    }

    public async Task<IReadOnlyList<int>> FindUserIdsByTenantCodeAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken) =>
        await db.TenantMembers
            .Where(member => member.TenantType == tenantType
                             && member.Status == TenantMemberStatuses.Active

                             // Whole-dimension rows match on the flag, never on the sentinel code.
                             && (member.ScopeAll || member.TenantCode == tenantCode))
            .Select(member => member.UserId)
            .Distinct()
            .OrderBy(userId => userId)
            .ToListAsync(cancellationToken);

    /// <summary>
    /// The same audience, narrowed to holders of one permission code.
    /// <para>
    /// The permission is joined back through <c>member_id</c>, so it must be held <b>on this very
    /// membership</b>; holding it in some other company does not put a person on this company's
    /// list. An empty permission code is rejected rather than ignored, because ignoring it would
    /// silently widen the result to every member of the tenant.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<int>> FindUserIdsByCompanyCodeAndPermissionAsync(
        string companyCode, string permissionCode, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permissionCode);

        return await db.Database
            .SqlQuery<int>(
                $"""
                 SELECT DISTINCT tm.user_id AS "Value"
                 FROM iam.tenant_members tm
                 JOIN iam.user_tenant_roles utr ON utr.member_id = tm.id
                 JOIN iam.role_permissions rp ON rp.role_id = utr.role_id
                 JOIN iam.permissions p ON p.id = rp.permission_id
                 WHERE tm.tenant_type = 'company'
                   AND tm.status = 'ACTIVE'
                   AND (tm.scope_all OR tm.tenant_code = {companyCode})
                   AND p.code = {permissionCode}
                   AND p.status = 'ACTIVE'
                 ORDER BY tm.user_id
                 """)
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<TenantMember>> FindAdminsByTenantsAsync(
        string tenantType, IReadOnlyCollection<string> tenantCodes, CancellationToken cancellationToken)
    {
        if (tenantCodes.Count == 0)
        {
            return [];
        }

        var codes = tenantCodes.ToArray();

        return await db.TenantMembers
            .Where(member => member.TenantType == tenantType
                             && codes.Contains(member.TenantCode)
                             && member.IsAdmin
                             && member.Status == TenantMemberStatuses.Active)
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyDictionary<string, int>> CountActiveByTenantsAsync(
        string tenantType, IReadOnlyCollection<string> tenantCodes, CancellationToken cancellationToken)
    {
        if (tenantCodes.Count == 0)
        {
            return new Dictionary<string, int>(StringComparer.Ordinal);
        }

        var codes = tenantCodes.ToArray();

        var counts = await db.TenantMembers
            .Where(member => member.TenantType == tenantType
                             && codes.Contains(member.TenantCode)
                             && member.Status == TenantMemberStatuses.Active)
            .GroupBy(member => member.TenantCode)
            .Select(group => new { Code = group.Key, Count = group.Count() })
            .ToListAsync(cancellationToken);

        // Codes with no members are absent rather than zero - the caller decides what "none" means.
        return counts.ToDictionary(row => row.Code, row => row.Count, StringComparer.Ordinal);
    }

    public async Task<IReadOnlyList<TenantMember>> ListActiveMembersByTenantCodeAsync(
        string tenantCode,
        IReadOnlyCollection<string> roleCodes,
        int limit,
        CancellationToken cancellationToken)
    {
        // Not filtered by tenant type: the two dimensions share one code namespace, and the caller
        // asking "who should hear about this tenant" has a code, not a dimension. Whole-dimension
        // rows are excluded because they answer a different question.
        var rows = db.TenantMembers.Where(member =>
            !member.ScopeAll
            && member.TenantCode == tenantCode
            && member.Status == TenantMemberStatuses.Active);

        if (roleCodes.Count > 0)
        {
            var codes = roleCodes.ToArray();

            // The role catalogue is another slice's table, so it is reached by raw SQL rather than
            // by a second entity mapping of it.
            var roleIds = await db.Database
                .SqlQuery<int>($"""SELECT id AS "Value" FROM iam.roles WHERE code = ANY({codes})""")
                .ToListAsync(cancellationToken);

            rows = rows.Where(member =>
                db.UserTenantRoles.Any(binding =>
                    binding.MemberId == member.Id && roleIds.Contains(binding.RoleId)));
        }

        rows = rows.OrderBy(member => member.UserId).ThenBy(member => member.Id);

        if (limit > 0)
        {
            rows = rows.Take(limit);
        }

        return await rows.ToListAsync(cancellationToken);
    }

    private IQueryable<TenantMember> ActiveAdmins(string tenantType, string tenantCode) =>
        db.TenantMembers
            .Where(member => member.TenantType == tenantType
                             && member.TenantCode == tenantCode
                             && member.IsAdmin
                             && member.Status == TenantMemberStatuses.Active)
            .OrderBy(member => member.Id);
}
