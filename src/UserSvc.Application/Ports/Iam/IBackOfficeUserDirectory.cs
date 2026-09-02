using UserSvc.Domain.Iam;

namespace UserSvc.Application.Ports.Iam;

/// <summary>
/// The handful of back-office account facts IAM depends on. The account itself belongs to the
/// back-office authentication slice; this port names only what role management reads and writes, so
/// neither side has to know the other's row shape.
/// </summary>
public interface IBackOfficeUserDirectory
{
    /// <summary>Null when no such account exists. An unknown id has no standing - it is not an
    /// error, it is a "no".</summary>
    Task<BackOfficeUserFlags?> FindFlagsAsync(int userId, CancellationToken cancellationToken);

    /// <summary>Set the platform super-administrator flag.</summary>
    Task GrantSuperAdminAsync(int userId, CancellationToken cancellationToken);

    /// <summary>
    /// Clear the flag <b>only if another active super administrator exists</b>, as a single atomic
    /// statement. Returns false when this account is the last one.
    /// <para>
    /// Read-then-write would let two concurrent revocations both observe a second administrator and
    /// both proceed, leaving the platform with none and no way back in. The check and the write have
    /// to be the same statement.
    /// </para>
    /// </summary>
    Task<bool> TryRevokeSuperAdminAsync(int userId, CancellationToken cancellationToken);

    /// <summary>
    /// Invalidate every access token already issued to these accounts by bumping their token
    /// version. Called after any change that narrows what an account may do.
    /// </summary>
    Task IncrementTokenVersionAsync(
        IReadOnlyCollection<int> userIds,
        CancellationToken cancellationToken);
}

/// <summary>
/// The back-office account fields IAM reads.
/// <para>
/// <c>IsSuperAdmin</c> is the platform super administrator, an <b>account-row</b> property: it holds
/// with zero tenant memberships, it is written only by its own endpoint, and it is re-read from the
/// database on every request rather than trusted from a token - a stale or forged claim must not be
/// able to escalate. <c>TokenVersion</c> is a generation counter; bumping it retires every access
/// token in flight.
/// </para>
/// </summary>
public sealed record BackOfficeUserFlags(
    int Id,
    string Status,
    bool IsSuperAdmin,
    int TokenVersion)
{
    public bool IsActive() => Status == BackOfficeUserStatuses.Active;
}
