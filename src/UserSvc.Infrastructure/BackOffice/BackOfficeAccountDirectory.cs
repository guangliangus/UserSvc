using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;
using UserSvc.Infrastructure.Persistence;
using UserSvc.Infrastructure.Persistence.Repositories;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// The parts of a back-office account the tenant slice reads and writes, over the account slice's
/// repositories.
/// <para>
/// Two methods do not come straight from a repository call and are worth knowing about.
/// <see cref="SearchUserIdsAsync"/> reproduces the directory's own matching rule - exact blind-index
/// lookup for an address, <see cref="BackendUserSearch.NameMatches"/> for anything else - by reusing
/// that expression rather than by writing a second definition of "matches what the operator typed".
/// <see cref="TouchLastLoginAsync"/> goes to the context because the account repository has no
/// method for it; it is one column and no other slice writes it.
/// </para>
/// </summary>
public sealed class BackOfficeAccountDirectory(
    IBackendUserRepository users,
    IBackendIdentityRepository identities,
    UserSvcDbContext db,
    IdentifierProtector protector,
    ILogger<BackOfficeAccountDirectory> logger) : IBackOfficeAccountDirectory
{
    /// <summary>Matches the account slice's own value for a write nobody authored by hand.</summary>
    private const string SystemActor = "system";

    public async Task<BackOfficeAccount?> FindAsync(int userId, CancellationToken cancellationToken)
    {
        var user = await users.ReadByIdAsync(userId, cancellationToken);
        return user is null ? null : Project(user);
    }

    public async Task<IReadOnlyList<BackOfficeAccount>> ListByIdsAsync(
        IReadOnlyCollection<int> userIds, CancellationToken cancellationToken) =>
        userIds.Count == 0
            ? []
            : [.. (await users.ListByIdsAsync([.. userIds], cancellationToken)).Select(Project)];

    /// <summary>
    /// An empty result means "matched nobody" and never "no filter" - the caller's roster query
    /// distinguishes the two, and this method must not collapse them by answering an empty term.
    /// A blank term is therefore refused as a match rather than treated as a wildcard.
    /// </summary>
    public async Task<IReadOnlyList<int>> SearchUserIdsAsync(string term, CancellationToken cancellationToken)
    {
        var trimmed = (term ?? string.Empty).Trim();
        if (trimmed.Length == 0)
        {
            return [];
        }

        if (BackendUserSearch.LooksLikeAddress(trimmed))
        {
            // An address is stored as a deterministic hash and a ciphertext, so there is nothing to
            // match a substring against: the whole address either hashes to a row or it does not.
            var normalized = BackOfficeIdentifiers.Normalize(BackendIdentityTypes.Email, trimmed);
            var identity = await identities.FindActiveAsync(
                BackendIdentityTypes.Email, protector.Hash(normalized), cancellationToken);

            return identity is null ? [] : [identity.UserId];
        }

        return await db.BackendUsers
            .AsNoTracking()
            .Where(BackendUserSearch.NameMatches(trimmed))
            .OrderBy(user => user.Id)
            .Select(user => user.Id)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Best effort, per the port: an account whose address cannot be decrypted is absent from the
    /// result rather than failing the roster. The log line carries the user id and the key version
    /// because without it a key outage degrades every row on the page to a dash behind a 200, and
    /// nothing anywhere would say why.
    /// </summary>
    public async Task<IReadOnlyDictionary<int, string>> ListPrimaryEmailsAsync(
        IReadOnlyCollection<int> userIds, CancellationToken cancellationToken)
    {
        var emails = new Dictionary<int, string>();
        if (userIds.Count == 0)
        {
            return emails;
        }

        var rows = await identities.ListActiveByUserIdsAsync([.. userIds], cancellationToken);

        // Ordered by id, so "the first e-mail identity" is the same one on every page load.
        foreach (var identity in rows)
        {
            if (identity.IdentityType != BackendIdentityTypes.Email
                || emails.ContainsKey(identity.UserId)
                || string.IsNullOrEmpty(identity.IdentifierCiphertext))
            {
                continue;
            }

            try
            {
                emails[identity.UserId] = protector.Decrypt(identity.IdentifierCiphertext);
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException)
            {
                logger.LogError(
                    ex,
                    "The e-mail identity of back-office account {UserId} could not be decrypted "
                    + "(key version {KeyVersion}); the account is absent from this roster page.",
                    identity.UserId,
                    identity.KeyVersion);
            }
        }

        return emails;
    }

    /// <summary>
    /// <paramref name="algorithm"/> is accepted and not stored: <c>iam.backend_users</c> has no
    /// algorithm column - unlike the consumer <c>identity</c> schema, which does - and the Argon2
    /// encoding already names its own parameters inside the hash string. Inventing a column for it
    /// would be a schema change on a table that matches the live database exactly.
    /// </summary>
    public async Task SetPasswordHashAsync(
        int userId, string passwordHash, string algorithm, CancellationToken cancellationToken) =>
        await users.UpdatePasswordHashAsync(userId, passwordHash, SystemActor, cancellationToken);

    public Task IncrementTokenVersionAsync(int userId, CancellationToken cancellationToken) =>
        users.IncrementTokenVersionAsync([userId], cancellationToken);

    /// <summary>
    /// Deliberately not stamping <c>updated_at</c>/<c>updated_by</c>: a sign-in is not an edit of
    /// the account, and letting it move the modification stamp would make every account look freshly
    /// changed and bury the edits an operator is actually looking for.
    /// </summary>
    public Task TouchLastLoginAsync(int userId, DateTimeOffset when, CancellationToken cancellationToken) =>
        db.BackendUsers
            .Where(user => user.Id == userId)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(user => user.LastLoginAt, when),
                cancellationToken);

    private static BackOfficeAccount Project(BackendUser user) => new(
        user.Id,
        user.FirstName ?? string.Empty,
        user.LastName ?? string.Empty,
        user.Nickname ?? string.Empty,
        user.StaffCode ?? string.Empty,
        user.Status,
        user.Origin,
        user.IsSuperAdmin,
        user.TokenVersion,
        user.LastLoginAt);
}
