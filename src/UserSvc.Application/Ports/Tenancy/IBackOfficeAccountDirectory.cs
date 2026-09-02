namespace UserSvc.Application.Ports.Tenancy;

/// <summary>
/// The parts of a back-office account this slice reads.
/// <para>
/// <c>Status</c> is PENDING | ACTIVE | DISABLED, and only ACTIVE carries authority - the other two
/// may hold a session that simply carries nothing. <c>Origin</c> is INTERNAL (an HR-provisioned
/// staff account, which has no local password to reset) or EXTERNAL (an account this back office
/// created).
/// </para>
/// </summary>
public sealed record BackOfficeAccount(
    int Id,
    string FirstName,
    string LastName,
    string Nickname,
    string StaffCode,
    string Status,
    string Origin,
    bool IsSuperAdmin,
    int TokenVersion,
    DateTimeOffset? LastLoginAt);

/// <summary>Read and write outlet for back-office accounts, as tenancy needs them.</summary>
public interface IBackOfficeAccountDirectory
{
    Task<BackOfficeAccount?> FindAsync(int userId, CancellationToken cancellationToken);

    Task<IReadOnlyList<BackOfficeAccount>> ListByIdsAsync(
        IReadOnlyCollection<int> userIds, CancellationToken cancellationToken);

    /// <summary>
    /// Accounts matching a roster keyword. A term that looks like an e-mail address is matched
    /// <b>exactly</b> against its blind index - the address itself is encrypted, so there is no
    /// substring to match on - and anything else fuzzily against the name and staff-code fields.
    /// An empty result means the search found nobody, and callers must not read that as "no filter".
    /// </summary>
    Task<IReadOnlyList<int>> SearchUserIdsAsync(string term, CancellationToken cancellationToken);

    /// <summary>
    /// First active e-mail per account, decrypted. <b>Best effort</b>: an account whose identity
    /// cannot be decrypted is absent from the result rather than failing the roster - but the
    /// implementation must log the user id and key version, because a key outage otherwise
    /// degrades every row to a dash behind a 200.
    /// </summary>
    Task<IReadOnlyDictionary<int, string>> ListPrimaryEmailsAsync(
        IReadOnlyCollection<int> userIds, CancellationToken cancellationToken);

    Task SetPasswordHashAsync(
        int userId, string passwordHash, string algorithm, CancellationToken cancellationToken);

    /// <summary>
    /// Bumps <c>token_version</c>, which is what makes a membership change land on the very next
    /// request instead of at the next sign-in.
    /// </summary>
    Task IncrementTokenVersionAsync(int userId, CancellationToken cancellationToken);

    Task TouchLastLoginAsync(int userId, DateTimeOffset when, CancellationToken cancellationToken);
}
