using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Users;
using UserSvc.Domain.Users;

namespace UserSvc.Infrastructure.Persistence.Repositories;

public sealed class UserIdentityRepository(UserSvcDbContext db) : IUserIdentityRepository
{
    /// <summary>
    /// Reads with change tracking disabled: the caller only asks whether the identifier is taken
    /// and never writes to what comes back, so tracking it would cost a snapshot and, worse, make
    /// a later accidental mutation savable.
    /// </summary>
    public Task<UserIdentity?> FindActiveAsync(
        string identityType,
        string identifierHash,
        CancellationToken cancellationToken) =>
        db.UserIdentities
            .AsNoTracking()
            .FirstOrDefaultAsync(
                i => i.IdentityType == identityType
                     && i.IdentifierHash == identifierHash
                     && i.Status == UserStatuses.Active,
                cancellationToken);

    public Task<UserIdentity?> FindActiveByIdentifierAndProviderAsync(
        string identityType,
        string identifierHash,
        string provider,
        CancellationToken cancellationToken) =>
        db.UserIdentities
            .AsNoTracking()
            .FirstOrDefaultAsync(
                i => i.IdentityType == identityType
                     && i.IdentifierHash == identifierHash
                     && i.Provider == provider
                     && i.Status == UserStatuses.Active,
                cancellationToken);

    public Task<UserIdentity?> FindActiveByProviderAsync(
        string identityType,
        string provider,
        string providerUid,
        CancellationToken cancellationToken) =>
        db.UserIdentities
            .AsNoTracking()
            .FirstOrDefaultAsync(
                i => i.IdentityType == identityType
                     && i.Provider == provider
                     && i.ProviderUid == providerUid
                     && i.Status == UserStatuses.Active,
                cancellationToken);

    /// <summary>
    /// Ordered by id rather than by created_at: both are monotonic for inserts, and the primary key
    /// is already the tie-break the planner would fall back on. Two rows written in one transaction
    /// share a created_at to the microsecond, which would otherwise make "earliest" ambiguous.
    /// </summary>
    public Task<UserIdentity?> FindEarliestActiveWechatByUnionIdAsync(
        string unionId,
        CancellationToken cancellationToken) =>
        db.UserIdentities
            .AsNoTracking()
            .Where(i => (i.IdentityType == IdentityTypes.Wechat || i.IdentityType == IdentityTypes.WechatMini)
                        && i.ProviderUid == unionId
                        && i.Status == UserStatuses.Active)
            .OrderBy(i => i.Id)
            .FirstOrDefaultAsync(cancellationToken);

    /// <summary>
    /// TRACKED, unlike the single-row lookups above. Deregistration unbinds every row this returns,
    /// and the linked-accounts view simply does not write - one method serving both beats two that
    /// differ only in tracking and invite the wrong call.
    /// </summary>
    public async Task<IReadOnlyList<UserIdentity>> ListActiveByUserAsync(
        int userId,
        CancellationToken cancellationToken) =>
        await db.UserIdentities
            .Where(i => i.UserId == userId && i.Status == UserStatuses.Active)
            .OrderBy(i => i.Id)
            .ToListAsync(cancellationToken);

    /// <summary>
    /// Attaches a detached instance as Modified. The xmin concurrency token came back with the read,
    /// so the UPDATE still carries its original-value predicate and a row someone else changed in
    /// between fails loudly rather than silently losing their write.
    /// </summary>
    public void Update(UserIdentity identity) => db.UserIdentities.Update(identity);
}
