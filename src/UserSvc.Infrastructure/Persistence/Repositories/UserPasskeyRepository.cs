using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Auth;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Security;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Users;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>The credential table, and nothing else.</summary>
public sealed class UserPasskeyRepository(UserSvcDbContext db) : IUserPasskeyRepository
{
    /// <summary>
    /// Tracked, not <c>AsNoTracking</c>: the caller advances the signature counter on the row this
    /// returns, and an untracked entity would accept the mutation and then never save it - a clone
    /// check that quietly stops counting.
    /// </summary>
    public Task<UserPasskey?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken) =>
        db.UserPasskeys.FirstOrDefaultAsync(p => p.CredentialId == credentialId, cancellationToken);

    /// <summary>Tracked as well - rename and delete both write to what this returns.</summary>
    public Task<UserPasskey?> FindByIdAsync(int id, CancellationToken cancellationToken) =>
        db.UserPasskeys.FirstOrDefaultAsync(p => p.Id == id, cancellationToken);

    public async Task<IReadOnlyList<UserPasskey>> ListByUserAsync(int userId, CancellationToken cancellationToken) =>
        await db.UserPasskeys
            .AsNoTracking()
            .Where(p => p.UserId == userId)
            .OrderBy(p => p.CreatedAt)
            .ThenBy(p => p.Id)
            .ToListAsync(cancellationToken);

    public Task<int> CountByUserAsync(int userId, CancellationToken cancellationToken) =>
        db.UserPasskeys.CountAsync(p => p.UserId == userId, cancellationToken);

    public void Add(UserPasskey passkey) => db.UserPasskeys.Add(passkey);

    public void Remove(UserPasskey passkey) => db.UserPasskeys.Remove(passkey);
}

/// <summary>
/// The seam between the passkey slice and the login-identity table it does not own.
/// <para>
/// Both writes here are projections over rows another slice is responsible for, which is why this
/// is a separate adapter rather than more methods on <see cref="UserPasskeyRepository"/>, and why
/// it never calls <c>SaveChanges</c> - it stages its work inside the transaction its caller opened.
/// </para>
/// <para>
/// The companion row's identifier is a synthetic <c>passkey:{userId}</c>, protected with the same
/// blind index and envelope encryption as a real address (decision 13). It is synthetic because
/// there is no address to store - the point of the row is that the capability is <i>listed</i>,
/// not that it is looked up - but it goes through <see cref="IdentifierProtector"/> anyway, because
/// the partial unique index lives on <c>identifier_hash</c> and a row that skipped the hash would
/// be the one row in the table that could be duplicated.
/// </para>
/// </summary>
public sealed class PasskeyIdentityLink(
    UserSvcDbContext db,
    IdentifierProtector protector,
    IClock clock) : IPasskeyIdentityLink
{
    /// <summary>
    /// The status a retired identity carries.
    /// <para>
    /// Spelled here as a literal because the identities slice has no shared constant for the
    /// identity-status vocabulary yet - <c>UserStatuses</c> describes accounts, and borrowing its
    /// <c>DISABLED</c> would say an administrator switched this login off when the truth is that
    /// the user removed their last passkey. It belongs in a <c>IdentityStatuses</c> type the moment
    /// one exists.
    /// </para>
    /// </summary>
    private const string UnboundStatus = "UNBOUND";

    public async Task<bool> HasNonPasskeyLoginMethodAsync(int userId, CancellationToken cancellationToken)
    {
        var hasOtherIdentity = await db.UserIdentities
            .AsNoTracking()
            .AnyAsync(
                i => i.UserId == userId
                     && i.Status == UserStatuses.Active
                     && i.IdentityType != IdentityTypes.Passkey,
                cancellationToken);

        if (hasOtherIdentity)
        {
            return true;
        }

        // A password counts on its own, which is the Go service's rule and is kept deliberately.
        // It is not airtight: an account whose only identity row is the PASSKEY companion has a
        // password but nothing to present it with, so "has a password" can still be a lockout.
        // Tightening it would make some deletes newly impossible for accounts that are fine today,
        // which is a product decision rather than one to take here - see the follow-up note.
        return await db.Users
            .AsNoTracking()
            .AnyAsync(u => u.Id == userId && u.PasswordHash != string.Empty, cancellationToken);
    }

    public async Task EnsurePasskeyIdentityAsync(int userId, CancellationToken cancellationToken)
    {
        // Filed by user and type rather than by the identifier hash: the row is unique per account
        // by construction, and this way the query costs no HMAC on the path that finds one - which
        // is every registration after the first.
        //
        // The query runs on the caller's connection, so it sees whatever this transaction has
        // already written; it does not see an insert still staged in the change tracker, which is
        // why this must not be called twice before a save.
        var existing = await db.UserIdentities
            .FirstOrDefaultAsync(
                i => i.UserId == userId && i.IdentityType == IdentityTypes.Passkey,
                cancellationToken);

        var now = clock.UtcNow;

        if (existing is not null)
        {
            // Re-enrolling after removing the last credential revives the row that was retired
            // then, rather than inserting a second one the partial unique index would refuse.
            if (existing.Status != UserStatuses.Active)
            {
                existing.Status = UserStatuses.Active;
                existing.UpdatedAt = now;
            }

            return;
        }

        var identifier = PasskeyIdentifierFor(userId);

        db.UserIdentities.Add(new UserIdentity
        {
            UserId = userId,
            IdentityType = IdentityTypes.Passkey,
            IdentifierHash = protector.Hash(identifier),
            IdentifierCiphertext = protector.Encrypt(identifier),
            IdentifierKeyVersion = protector.KeyVersion,
            Status = UserStatuses.Active,
            CreatedAt = now,
            UpdatedAt = now,
        });
    }

    public async Task RetirePasskeyIdentityAsync(int userId, CancellationToken cancellationToken)
    {
        var existing = await db.UserIdentities
            .FirstOrDefaultAsync(
                i => i.UserId == userId
                     && i.IdentityType == IdentityTypes.Passkey
                     && i.Status == UserStatuses.Active,
                cancellationToken);

        if (existing is null)
        {
            return;
        }

        existing.Status = UnboundStatus;
        existing.UpdatedAt = clock.UtcNow;
    }

    /// <summary>The synthetic identifier the companion row is filed under. Per account, so two
    /// accounts never collide on the blind index.</summary>
    private static string PasskeyIdentifierFor(int userId) =>
        $"passkey:{userId.ToString(System.Globalization.CultureInfo.InvariantCulture)}";
}
