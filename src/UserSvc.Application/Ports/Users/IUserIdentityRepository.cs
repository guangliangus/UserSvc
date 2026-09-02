using UserSvc.Domain.Users;

namespace UserSvc.Application.Ports.Users;

/// <summary>
/// Login identities - the rows that map a phone number or an email address to an account. There is
/// a database on the other side, so it is a port.
/// <para>
/// <b>There is deliberately no Add.</b> A new identity is created by adding it to
/// <c>User.Identities</c>, which lets EF fill <c>user_id</c> from the key it just generated; an
/// Add here would need that id to exist first and so would force a second SaveChanges. Rebinding
/// an existing identity is a different operation and will arrive with the slice that owns it.
/// </para>
/// </summary>
public interface IUserIdentityRepository
{
    /// <summary>
    /// Exact lookup by blind index (decision 13): the plaintext is not stored, so the match happens
    /// on <c>HMAC(identifier)</c>. Only ACTIVE rows count - an unbound identity is precisely one
    /// that someone else may now claim.
    /// </summary>
    Task<UserIdentity?> FindActiveAsync(
        string identityType,
        string identifierHash,
        CancellationToken cancellationToken);
}
