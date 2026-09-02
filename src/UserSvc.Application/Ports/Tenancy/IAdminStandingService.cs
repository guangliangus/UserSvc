namespace UserSvc.Application.Ports.Tenancy;

/// <summary>
/// Standing questions that are answered from the database and <b>never</b> from the token.
/// A token says what was true when it was minted; these two decide whether an account may take
/// somebody else's access away, so they are re-read every time.
/// </summary>
public interface IAdminStandingService
{
    /// <summary>Reads <c>iam.backend_users.is_super_admin</c>. Non-positive ids and missing rows
    /// answer false rather than throwing - "not a super administrator" is the safe answer to every
    /// malformed question.</summary>
    Task<bool> IsPlatformSuperAdminAsync(int userId, CancellationToken cancellationToken);

    /// <summary>
    /// Gate R3: the caller is the platform super administrator, or holds an administrator role in
    /// the target tenant (or on the whole-dimension row covering it).
    /// </summary>
    Task<bool> CanManageMembersAsync(
        int callerUserId, string tenantType, string tenantCode, CancellationToken cancellationToken);
}
