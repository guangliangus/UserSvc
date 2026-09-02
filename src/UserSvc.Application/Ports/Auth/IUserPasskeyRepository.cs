using UserSvc.Domain.Auth;

namespace UserSvc.Application.Ports.Auth;

/// <summary>
/// The passkey credential table. There is a database on the other side, so it is a port.
/// </summary>
public interface IUserPasskeyRepository
{
    /// <summary>
    /// Locates a credential by its raw WebAuthn credential id. This is the <b>only</b> lookup a
    /// discoverable login has: the client sends a credential and nothing else, and this query is
    /// what turns it into an account. It is deliberately not filtered by user.
    /// </summary>
    Task<UserPasskey?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken);

    /// <summary>
    /// Reads one credential by primary key, <b>without</b> filtering on the owner. Ownership is
    /// checked by the application service, which answers 404 for someone else's credential rather
    /// than 403 - a 403 would confirm that the id exists and belongs to somebody.
    /// </summary>
    Task<UserPasskey?> FindByIdAsync(int id, CancellationToken cancellationToken);

    /// <summary>Every credential the account holds, oldest first.</summary>
    Task<IReadOnlyList<UserPasskey>> ListByUserAsync(int userId, CancellationToken cancellationToken);

    /// <summary>How many credentials the account holds. Asked before a delete, to recognise the
    /// last one.</summary>
    Task<int> CountByUserAsync(int userId, CancellationToken cancellationToken);

    void Add(UserPasskey passkey);

    /// <summary>
    /// Removes the row for good.
    /// <para>
    /// <b>A physical delete, against the house rule that rows are retired rather than deleted</b>,
    /// and the credential table is the one place that rule is wrong. A retired credential row would
    /// keep occupying the unique index on <c>credential_id</c>, so a user who removed a key and
    /// then re-enrolled the same authenticator could never register it again. There is also nothing
    /// to audit in the row itself - the public key is worthless once the user has revoked it.
    /// </para>
    /// </summary>
    void Remove(UserPasskey passkey);
}

/// <summary>
/// This slice's narrow view of the neighbouring login-identity table - the seam between passkeys
/// and the identities slice, in the same spirit as the other cross-slice directories wired up in
/// <c>DependencyInjection</c>.
/// <para>
/// It exists because two questions this slice must answer live in a table it does not own:
/// "does this account still have another way in?" (asked before removing the last passkey) and
/// "does the login-methods screen know this account has passkeys?" (a companion
/// <c>user_identities</c> row of type PASSKEY, which is what makes the capability visible to a
/// slice that never reads <c>user_passkeys</c>).
/// </para>
/// <para>
/// It is a separate interface from <see cref="IUserPasskeyRepository"/> rather than more methods on
/// it, because the two touch different tables and only this one is a cross-slice reach. Both writes
/// run inside a transaction their caller opened.
/// </para>
/// </summary>
public interface IPasskeyIdentityLink
{
    /// <summary>
    /// Whether the account can still sign in without a passkey - any active login identity that is
    /// not the PASSKEY companion row, or a password on the account.
    /// </summary>
    Task<bool> HasNonPasskeyLoginMethodAsync(int userId, CancellationToken cancellationToken);

    /// <summary>
    /// Makes sure the account carries exactly one active PASSKEY identity row. Idempotent: called
    /// on every registration, does nothing when the row is already there.
    /// </summary>
    Task EnsurePasskeyIdentityAsync(int userId, CancellationToken cancellationToken);

    /// <summary>
    /// Retires the companion row when the account's last passkey is removed. Retires rather than
    /// deletes, which is the right rule for an identity row: the partial unique index is on active
    /// rows only, so an UNBOUND row does not block re-registering later.
    /// </summary>
    Task RetirePasskeyIdentityAsync(int userId, CancellationToken cancellationToken);
}
