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

    /// <summary>
    /// The same exact lookup, narrowed to one provider inside the identity type. Firebase needs it:
    /// one account may hold a <c>google.com</c> and an <c>apple.com</c> identity, both of them
    /// <c>FIREBASE</c> rows, so matching on type and hash alone can find the wrong one.
    /// </summary>
    Task<UserIdentity?> FindActiveByIdentifierAndProviderAsync(
        string identityType,
        string identifierHash,
        string provider,
        CancellationToken cancellationToken);

    /// <summary>
    /// Lookup by the provider's own subject rather than by the hashed identifier. This is the key
    /// the unique index enforces, and it exists because the identifier can go stale while the
    /// account does not: Firebase mints a new uid when its user record is deleted and re-created
    /// for the same Google or Apple account. The provider's sub does not move.
    /// </summary>
    Task<UserIdentity?> FindActiveByProviderAsync(
        string identityType,
        string provider,
        string providerUid,
        CancellationToken cancellationToken);

    /// <summary>
    /// The <b>earliest</b> active WeChat or mini-program identity carrying this union id. Earliest,
    /// not any: one human can hold one row per WeChat application, and the oldest is the account
    /// the others unify into. Picking arbitrarily would make the resolved account depend on row order.
    /// </summary>
    Task<UserIdentity?> FindEarliestActiveWechatByUnionIdAsync(
        string unionId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Every ACTIVE identity of one account.
    /// <para>
    /// Deliberately TRACKED, unlike the lookups above. Two callers want this list: the
    /// linked-accounts view, which only reads, and deregistration, which unbinds every row it gets
    /// back. Tracking serves both - a reader simply does not write - whereas two methods differing
    /// only in tracking is an invitation to call the wrong one.
    /// </para>
    /// </summary>
    Task<IReadOnlyList<UserIdentity>> ListActiveByUserAsync(int userId, CancellationToken cancellationToken);

    /// <summary>
    /// Marks an identity read earlier as changed, so the next <c>SaveChanges</c> writes it. Needed
    /// because the single-row lookups are untracked and two flows correct what they read: the
    /// WeChat union-id backfill, and re-pointing a Firebase identity at the provider's current uid.
    /// There is still no Add - a new identity goes through <c>User.Identities</c> so EF can fill
    /// <c>user_id</c> from the key it just generated.
    /// </summary>
    void Update(UserIdentity identity);
}
