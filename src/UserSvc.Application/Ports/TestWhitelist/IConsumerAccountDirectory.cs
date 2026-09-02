namespace UserSvc.Application.Ports.TestWhitelist;

/// <summary>
/// The fields a consumer's display name can be composed from, and nothing else.
/// <para>
/// <b>No status.</b> It was here, read out of the database on every listing, and nothing ever
/// looked at it: the summary reports only whether the row exists, and the one guard that cares
/// whether an account can still sign in - adding somebody to the whitelist - asks
/// <c>IUserRepository</c> for the account itself rather than this projection. A column nobody reads
/// is not free on a path that exists to bound what leaves the consumer schema, so it is gone. If a
/// screen ever needs to show "this tester's account was disabled", it arrives with the response
/// field that shows it.
/// </para>
/// </summary>
public sealed record ConsumerAccountRow(
    int UserId,
    string FirstName,
    string LastName,
    string Nickname);

/// <summary>
/// One ACTIVE contact identity of a consumer account, <b>as stored</b>.
/// <para>
/// The identifier comes back as ciphertext and never as plaintext, because deciding what an
/// operator may see is a policy question and this is a persistence port. The consumer identity
/// table stores no masked copy - unlike the back-office one - so the mask has to be derived, and
/// the layer that holds the data key is the layer that derives it.
/// </para>
/// </summary>
public sealed record ConsumerContactRow(
    int UserId,
    string IdentityType,
    string IdentifierCiphertext);

/// <summary>
/// The window onto consumer accounts that the back office needs in order to say "yes, that is the
/// tester". A port because there is a database behind it, and because every guard in front of it
/// has to be testable without one.
/// <para>
/// <b>This crosses the boundary between the two bounded contexts</b>, from a back-office endpoint
/// into the consumer schema, and the shape is what keeps the crossing narrow: batch projections of
/// four name fields and one ciphertext, no entity, no write path, and no way to ask for anything
/// but a set of ids somebody already holds. Resolving a contact detail to an id is deliberately
/// <i>not</i> here - that is an exact blind-index lookup, and
/// <c>IUserIdentityRepository.FindActiveAsync</c> already answers it.
/// </para>
/// </summary>
public interface IConsumerAccountDirectory
{
    /// <summary>
    /// The named accounts, in no particular order. An id with no row is simply absent: a whitelist
    /// entry whose account is gone must stay listable, so "missing" is a value the caller renders
    /// rather than an error. An empty input answers empty without querying.
    /// </summary>
    Task<IReadOnlyList<ConsumerAccountRow>> ListAccountsAsync(
        IReadOnlyList<int> userIds, CancellationToken cancellationToken);

    /// <summary>
    /// The ACTIVE phone and email identities of the named accounts, <b>id ascending</b>. The order
    /// is part of the contract: the caller reports the first identity of each type, and an
    /// unordered read would show the same account two different addresses on two page loads.
    /// <para>
    /// Third-party identities (a social login, a passkey) are excluded. They are not contact
    /// details, and an operator confirming a tester has no use for a provider subject.
    /// </para>
    /// </summary>
    Task<IReadOnlyList<ConsumerContactRow>> ListActiveContactsAsync(
        IReadOnlyList<int> userIds, CancellationToken cancellationToken);
}
