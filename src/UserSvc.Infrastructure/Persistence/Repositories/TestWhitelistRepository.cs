using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.TestWhitelist;
using UserSvc.Domain.TestWhitelist;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// EF Core adapter for the consumer test-user whitelist, over the shared persistence context.
/// </summary>
public sealed class TestWhitelistRepository(UserSvcDbContext db) : ITestWhitelistRepository
{
    /// <summary>Reached through <c>DbContext.Set&lt;T&gt;()</c> rather than a property on the
    /// shared context; the configuration is what maps the entity.</summary>
    private DbSet<TestWhitelistEntry> Entries => db.Set<TestWhitelistEntry>();

    public void Add(TestWhitelistEntry entry) => Entries.Add(entry);

    /// <summary>
    /// One indexed existence check, untracked - it answers a boolean on the hottest authenticated
    /// path in the platform and has no use for a row or for change tracking.
    /// </summary>
    public Task<bool> IsWhitelistedAsync(int userId, CancellationToken cancellationToken) =>
        Entries
            .AsNoTracking()
            .AnyAsync(
                entry => entry.UserId == userId && entry.Status == TestWhitelistStatuses.Active,
                cancellationToken);

    /// <summary>
    /// This account's entry whatever its status, tracked so the caller can revive or retire it.
    /// <para>
    /// The write paths keep at most one row per account - a re-add revives the row it finds - so
    /// the ordering only ever matters against a hand-edited table. It prefers the ACTIVE row
    /// anyway: reviving a stray REMOVED row while an ACTIVE one existed would be refused by the
    /// partial unique index, which is a confusing 409 for an operation that was already done.
    /// </para>
    /// </summary>
    public Task<TestWhitelistEntry?> FindAsync(int userId, CancellationToken cancellationToken) =>
        Entries
            .Where(entry => entry.UserId == userId)
            .OrderByDescending(entry => entry.Status == TestWhitelistStatuses.Active)
            .ThenByDescending(entry => entry.Id)
            .FirstOrDefaultAsync(cancellationToken);

    /// <summary>
    /// Every whitelisted account id, ascending, untracked and projected to the id.
    /// <para>
    /// The sort is in the database and is part of the contract: it is what makes the caller's paging
    /// stable between two requests.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<int>> ListActiveUserIdsAsync(CancellationToken cancellationToken) =>
        await Entries
            .AsNoTracking()
            .Where(entry => entry.Status == TestWhitelistStatuses.Active)
            .OrderBy(entry => entry.UserId)
            .Select(entry => entry.UserId)
            .ToListAsync(cancellationToken);
}
