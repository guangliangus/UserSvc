using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Iam;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// The handful of back-office account facts role management depends on, over the account slice's
/// own repository.
/// <para>
/// All four methods already exist there under different names and with an extra parameter: the
/// account repository stamps <c>updated_by</c> on every write, and this port carries no actor. It
/// is written as <see cref="SystemActor"/> rather than left blank or invented, because these three
/// writes are never authored by the row's owner - a super-administrator grant, its revocation and a
/// token-version bump are all consequences of somebody else's decision, and who made it is recorded
/// in the IAM audit trail where it can carry a name and a request id.
/// </para>
/// </summary>
public sealed class BackOfficeUserDirectory(IBackendUserRepository users) : IBackOfficeUserDirectory
{
    /// <summary>Matches the value the account slice writes for the same reason - see
    /// <c>BackOfficeAccountAppService</c>.</summary>
    private const string SystemActor = "system";

    /// <summary>
    /// A no-tracking read: the caller inspects the flags and never writes back through them, and a
    /// tracked copy here would fight the single-statement updates below.
    /// </summary>
    public async Task<BackOfficeUserFlags?> FindFlagsAsync(int userId, CancellationToken cancellationToken)
    {
        var user = await users.ReadByIdAsync(userId, cancellationToken);
        return user is null
            ? null
            : new BackOfficeUserFlags(user.Id, user.Status, user.IsSuperAdmin, user.TokenVersion);
    }

    public async Task GrantSuperAdminAsync(int userId, CancellationToken cancellationToken) =>
        await users.GrantSuperAdminAsync(userId, SystemActor, cancellationToken);

    /// <summary>
    /// The atomic revoke. The repository's guard is one statement whose WHERE clause requires
    /// another active super administrator to exist, so the "am I the last one" question and the
    /// write cannot be interleaved - which is the whole point, and why this method exists rather
    /// than a read followed by a plain update.
    /// </summary>
    public Task<bool> TryRevokeSuperAdminAsync(int userId, CancellationToken cancellationToken) =>
        users.RevokeSuperAdminIfAnotherActiveExistsAsync(userId, SystemActor, cancellationToken);

    public Task IncrementTokenVersionAsync(
        IReadOnlyCollection<int> userIds, CancellationToken cancellationToken) =>
        users.IncrementTokenVersionAsync([.. userIds], cancellationToken);
}
