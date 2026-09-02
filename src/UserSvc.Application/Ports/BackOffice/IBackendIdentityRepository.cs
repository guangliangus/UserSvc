using UserSvc.Domain.BackOffice;

namespace UserSvc.Application.Ports.BackOffice;

/// <summary>
/// Back-office login identities - the rows that map a corporate mailbox, a phone number or an
/// employee number to a back-office account.
/// <para>
/// <b>Every lookup takes a blind index, never a plaintext identifier.</b> Normalizing and hashing
/// live in the application layer beside the flows that also have to write the ciphertext and the
/// mask, so the two can never drift: a repository that hashed on its own would be a second place
/// where "which spelling of this address gets hashed" is decided, and the day the two disagree the
/// partial unique index silently stops meaning "one account per address".
/// </para>
/// <para>
/// Reads are ACTIVE-only, which is what makes a revoked identity behave exactly like an identity
/// that never existed - the caller gets null and answers "no such account", with no separate
/// "this one is disabled" branch to leak the difference.
/// </para>
/// </summary>
public interface IBackendIdentityRepository
{
    /// <summary>
    /// Stages a new identity. Callers that are also creating the account should attach it to
    /// <see cref="BackendUser.Identities"/> instead, so EF fills <c>user_id</c> from the key the
    /// insert generates rather than needing two saves.
    /// </summary>
    void Add(BackendIdentity identity);

    /// <summary>
    /// The single ACTIVE identity of this type with this blind index, or null. The partial unique
    /// index guarantees there is at most one.
    /// </summary>
    Task<BackendIdentity?> FindActiveAsync(
        string identityType,
        string identifierHash,
        CancellationToken cancellationToken);

    /// <summary>This identity by id, but only while it is ACTIVE.</summary>
    Task<BackendIdentity?> FindActiveByIdAsync(int id, CancellationToken cancellationToken);

    /// <summary>Every ACTIVE identity of one account.</summary>
    Task<IReadOnlyList<BackendIdentity>> ListActiveByUserIdAsync(int userId, CancellationToken cancellationToken);

    /// <summary>
    /// Every ACTIVE identity of these accounts, <b>ordered by id ascending</b>. The order is part of
    /// the contract: callers pick "the first email identity" as the account's primary address, and
    /// an unordered read would let the same account show two different addresses on two page loads.
    /// An empty input returns empty without querying.
    /// </summary>
    Task<IReadOnlyList<BackendIdentity>> ListActiveByUserIdsAsync(
        IReadOnlyList<int> userIds,
        CancellationToken cancellationToken);

    /// <summary>
    /// Writes <c>status</c> on every identity of one account and returns how many rows moved -
    /// how an account is stripped of all its login doors at once. Zero rows is not an error: an
    /// account whose identities were already revoked is in the state the caller asked for.
    /// </summary>
    Task<int> UpdateStatusByUserIdAsync(
        int userId,
        string status,
        string actor,
        CancellationToken cancellationToken);
}
