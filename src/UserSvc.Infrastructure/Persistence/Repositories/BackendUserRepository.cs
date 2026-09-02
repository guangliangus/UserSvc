using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// Back-office accounts over EF Core.
/// <para>
/// Three kinds of write appear here and the difference is deliberate. Ordinary edits happen through
/// the change tracker, so one changed property writes one column. Single-column writes that must
/// not disturb anything else - the token-version bump above all - go through the update API, which
/// emits one UPDATE and touches nothing it was not told to. The two statements whose guard is a
/// rule about the whole table are raw SQL, in <see cref="BackendUserSql"/>, because that guard
/// cannot survive being split into a read and a write.
/// </para>
/// </summary>
public sealed class BackendUserRepository(
    UserSvcDbContext db,
    IdentifierProtector protector,
    IClock clock) : IBackendUserRepository
{
    /// <summary>The people picker is a picker, not an export.</summary>
    private const int OptionLimit = 20;

    public void Add(BackendUser user) => db.BackendUsers.Add(user);

    public Task<BackendUser?> FindByIdAsync(int id, CancellationToken cancellationToken) =>
        db.BackendUsers.FirstOrDefaultAsync(user => user.Id == id, cancellationToken);

    /// <summary>
    /// Untracked on purpose - see the port. A tracked read would answer from this unit of work's
    /// identity map, which is exactly wrong after a raw-SQL statement has changed the row underneath
    /// it.
    /// </summary>
    public Task<BackendUser?> ReadByIdAsync(int id, CancellationToken cancellationToken) =>
        db.BackendUsers.AsNoTracking().FirstOrDefaultAsync(user => user.Id == id, cancellationToken);

    public async Task<IReadOnlyList<BackendUser>> ListByIdsAsync(
        IReadOnlyList<int> ids,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ids);

        // An empty IN list is a query that can only return nothing; not sending it is not an
        // optimization so much as declining to ask.
        return ids.Count == 0
            ? []
            : await db.BackendUsers.AsNoTracking()
                .Where(user => ids.Contains(user.Id))
                .ToListAsync(cancellationToken);
    }

    public async Task<BackOfficeUserPage> ListAsync(
        BackOfficeUserQuery query,
        UserVisibilityFilter? visibility,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var accounts = db.BackendUsers.AsNoTracking();

        if (visibility is not null)
        {
            var visible = await VisibleUserIdsAsync(visibility, cancellationToken);
            if (visible.Count == 0)
            {
                return new BackOfficeUserPage([], 0);
            }

            accounts = accounts.Where(user => visible.Contains(user.Id));
        }

        if (!string.IsNullOrEmpty(query.Status))
        {
            accounts = accounts.Where(user => user.Status == query.Status);
        }

        accounts = ApplySearch(accounts, query.Search);

        var total = await accounts.CountAsync(cancellationToken);
        if (total == 0)
        {
            return new BackOfficeUserPage([], 0);
        }

        var page = Math.Max(1, query.Page);
        var pageSize = Math.Max(1, query.PageSize);

        var users = await accounts
            // Newest first, with the id as a tie-break. Seeded and bulk-provisioned accounts share
            // a timestamp to the microsecond, and an unstable sort makes a pager repeat one row on
            // page two while dropping another entirely - a data-loss-shaped bug with no data loss.
            .OrderByDescending(user => user.CreatedAt)
            .ThenByDescending(user => user.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);

        return new BackOfficeUserPage(users, total);
    }

    public async Task<IReadOnlyList<BackOfficeUserOption>> ListOptionsAsync(
        int userId,
        string? nickname,
        UserVisibilityFilter? visibility,
        CancellationToken cancellationToken)
    {
        var accounts = db.BackendUsers.AsNoTracking()
            .Where(user => user.Status == BackendUserStatuses.Active);

        if (visibility is not null)
        {
            var visible = await VisibleUserIdsAsync(visibility, cancellationToken);
            if (visible.Count == 0)
            {
                return [];
            }

            accounts = accounts.Where(user => visible.Contains(user.Id));
        }

        var limited = true;

        if (userId > 0)
        {
            // A lookup by id, not a search: one row at most, so the cap would be meaningless. It
            // still passes through the visibility filter, which is what stops this endpoint from
            // confirming any account's existence from a bare id.
            accounts = accounts.Where(user => user.Id == userId);
            limited = false;
        }
        else if (!string.IsNullOrWhiteSpace(nickname))
        {
            accounts = accounts.Where(BackendUserSearch.NameMatches(nickname));
        }

        accounts = accounts.OrderBy(user => user.Id);

        if (limited)
        {
            accounts = accounts.Take(OptionLimit);
        }

        return await accounts
            .Select(user => new BackOfficeUserOption(user.Id, user.FirstName, user.LastName, user.Nickname))
            .ToListAsync(cancellationToken);
    }

    public async Task<bool> UpdateStatusAsync(
        int id,
        string status,
        string actor,
        CancellationToken cancellationToken) =>
        await db.BackendUsers
            .Where(user => user.Id == id)
            .ExecuteUpdateAsync(
                update => update
                    .SetProperty(user => user.Status, status)
                    .SetProperty(user => user.UpdatedAt, clock.UtcNow)
                    .SetProperty(user => user.UpdatedBy, actor),
                cancellationToken) > 0;

    public async Task<bool> UpdatePasswordHashAsync(
        int id,
        string passwordHash,
        string actor,
        CancellationToken cancellationToken) =>
        await db.BackendUsers
            .Where(user => user.Id == id)
            .ExecuteUpdateAsync(
                update => update
                    .SetProperty(user => user.PasswordHash, passwordHash)
                    .SetProperty(user => user.UpdatedAt, clock.UtcNow)
                    .SetProperty(user => user.UpdatedBy, actor),
                cancellationToken) > 0;

    /// <summary>
    /// <b>Touches token_version and nothing else</b>, audit columns included. The bump is a
    /// consequence of somebody else's decision - a password reset, a promotion, a status change -
    /// and stamping this row as though the account had edited itself would misattribute it. The
    /// actor belongs in the audit trail, not in the row.
    /// <para>
    /// Unknown ids simply match nothing, which makes the call idempotent and safe to make with a
    /// set assembled optimistically.
    /// </para>
    /// </summary>
    public async Task IncrementTokenVersionAsync(IReadOnlyList<int> ids, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ids);

        if (ids.Count == 0)
        {
            return;
        }

        await db.BackendUsers
            .Where(user => ids.Contains(user.Id))
            .ExecuteUpdateAsync(
                update => update.SetProperty(user => user.TokenVersion, user => user.TokenVersion + 1),
                cancellationToken);
    }

    public Task<int> IncrementTokenVersionForEveryAccountAsync(CancellationToken cancellationToken) =>
        db.BackendUsers.ExecuteUpdateAsync(
            update => update.SetProperty(user => user.TokenVersion, user => user.TokenVersion + 1),
            cancellationToken);

    public async Task<IReadOnlyList<BackendUserTokenVersion>> ListTokenVersionsAsync(
        CancellationToken cancellationToken) =>
        await db.BackendUsers.AsNoTracking()
            .Select(user => new BackendUserTokenVersion(user.Id, user.TokenVersion))
            .ToListAsync(cancellationToken);

    public async Task<bool> GrantSuperAdminAsync(int id, string actor, CancellationToken cancellationToken) =>
        await db.BackendUsers
            .Where(user => user.Id == id)
            .ExecuteUpdateAsync(
                update => update
                    .SetProperty(user => user.IsSuperAdmin, true)
                    .SetProperty(user => user.UpdatedAt, clock.UtcNow)
                    .SetProperty(user => user.UpdatedBy, actor),
                cancellationToken) > 0;

    public async Task<bool> RevokeSuperAdminIfAnotherActiveExistsAsync(
        int id,
        string actor,
        CancellationToken cancellationToken) =>
        await db.Database.ExecuteSqlRawAsync(
            BackendUserSql.RevokeSuperAdminIfAnotherActiveExists,
            [actor, id],
            cancellationToken) > 0;

    public async Task<bool> SetStatusIfAnotherActiveSuperAdminExistsAsync(
        int id,
        string status,
        string actor,
        CancellationToken cancellationToken) =>
        await db.Database.ExecuteSqlRawAsync(
            BackendUserSql.SetStatusIfAnotherActiveSuperAdminExists,
            [status, actor, id],
            cancellationToken) > 0;

    /// <summary>
    /// Narrows the directory to what the search box asked for.
    /// <para>
    /// A complete address is resolved through the identity table's blind index - an exact match and
    /// only an exact match, because addresses are stored hashed rather than as text. Anything else
    /// is a name search. The branch is what keeps a name search from ever surfacing an address, and
    /// what makes an address search find the one account that owns it rather than everyone whose
    /// name happens to contain the same letters.
    /// </para>
    /// </summary>
    private IQueryable<BackendUser> ApplySearch(IQueryable<BackendUser> accounts, string? search)
    {
        var term = search?.Trim();

        // Blank means "no filter", never "match nothing" - a cleared search box shows the
        // directory again rather than an empty page.
        if (string.IsNullOrEmpty(term))
        {
            return accounts;
        }

        if (!BackendUserSearch.LooksLikeAddress(term))
        {
            return accounts.Where(BackendUserSearch.NameMatches(term));
        }

        var hash = protector.Hash(BackOfficeIdentifiers.Normalize(BackendIdentityTypes.Email, term));

        return accounts.Where(user => db.BackendIdentities.Any(identity =>
            identity.UserId == user.Id
            && identity.IdentityType == BackendIdentityTypes.Email
            && identity.Status == BackendIdentityStatuses.Active
            && identity.IdentifierHash == hash));
    }

    /// <summary>
    /// The set of accounts a scoped caller may see, read in one round trip.
    /// <para>
    /// Two queries rather than one composed statement, because the tenant membership table has no
    /// entity in this model yet and a raw fragment cannot be grafted into a LINQ query without
    /// giving up the rest of it. The set is bounded by the number of back-office accounts, which is
    /// in the hundreds; when the tenant module lands this collapses into an ordinary subquery.
    /// </para>
    /// </summary>
    private async Task<HashSet<int>> VisibleUserIdsAsync(
        UserVisibilityFilter visibility,
        CancellationToken cancellationToken)
    {
        // A caller who administers nothing sees nobody. Answered without a round trip, and kept
        // strictly apart from the null filter, which means unrestricted.
        if (visibility.MatchesNothing)
        {
            return [];
        }

        var dimensions = visibility.WholeDimensions.ToArray();
        var tenantTypes = visibility.Tenants.Select(tenant => tenant.TenantType).ToArray();
        var tenantCodes = visibility.Tenants.Select(tenant => tenant.TenantCode).ToArray();

        var ids = await db.Database
            .SqlQueryRaw<int>(BackendUserSql.VisibleUserIds, dimensions, tenantTypes, tenantCodes)
            .ToListAsync(cancellationToken);

        return [.. ids];
    }
}
