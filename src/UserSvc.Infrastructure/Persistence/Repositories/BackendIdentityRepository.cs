using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.BackOffice;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// Back-office login identities over EF Core.
/// <para>
/// Every read filters on ACTIVE, which is what lets a revoked identity behave exactly like one that
/// never existed. Callers get null and answer "no such account", with no second branch that would
/// let a stranger tell a revoked address from an unknown one.
/// </para>
/// </summary>
public sealed class BackendIdentityRepository(UserSvcDbContext db, IClock clock) : IBackendIdentityRepository
{
    public void Add(BackendIdentity identity) => db.BackendIdentities.Add(identity);

    /// <summary>
    /// Untracked: the caller is asking whether an address is taken and never writes to what comes
    /// back, so tracking it would cost a snapshot and make a later accidental mutation savable.
    /// </summary>
    public Task<BackendIdentity?> FindActiveAsync(
        string identityType,
        string identifierHash,
        CancellationToken cancellationToken) =>
        db.BackendIdentities
            .AsNoTracking()
            .FirstOrDefaultAsync(
                identity => identity.IdentityType == identityType
                            && identity.IdentifierHash == identifierHash
                            && identity.Status == BackendIdentityStatuses.Active,
                cancellationToken);

    public Task<BackendIdentity?> FindActiveByIdAsync(int id, CancellationToken cancellationToken) =>
        db.BackendIdentities
            .AsNoTracking()
            .FirstOrDefaultAsync(
                identity => identity.Id == id && identity.Status == BackendIdentityStatuses.Active,
                cancellationToken);

    public async Task<IReadOnlyList<BackendIdentity>> ListActiveByUserIdAsync(
        int userId,
        CancellationToken cancellationToken) =>
        await db.BackendIdentities
            .AsNoTracking()
            .Where(identity => identity.UserId == userId
                               && identity.Status == BackendIdentityStatuses.Active)
            .OrderBy(identity => identity.Id)
            .ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<BackendIdentity>> ListActiveByUserIdsAsync(
        IReadOnlyList<int> userIds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(userIds);

        return userIds.Count == 0
            ? []
            : await db.BackendIdentities
                .AsNoTracking()
                .Where(identity => userIds.Contains(identity.UserId)
                                   && identity.Status == BackendIdentityStatuses.Active)
                // Ascending id, because callers read "the first email identity" as the account's
                // primary address. Without a defined order the same account can show two different
                // addresses on two page loads.
                .OrderBy(identity => identity.Id)
                .ToListAsync(cancellationToken);
    }

    public Task<int> UpdateStatusByUserIdAsync(
        int userId,
        string status,
        string actor,
        CancellationToken cancellationToken) =>
        db.BackendIdentities
            .Where(identity => identity.UserId == userId)
            .ExecuteUpdateAsync(
                update => update
                    .SetProperty(identity => identity.Status, status)
                    .SetProperty(identity => identity.UpdatedAt, clock.UtcNow)
                    .SetProperty(identity => identity.UpdatedBy, actor),
                cancellationToken);
}
