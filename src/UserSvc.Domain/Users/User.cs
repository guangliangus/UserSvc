using UserSvc.Domain.Abstractions;
using UserSvc.Domain.Users.Events;

namespace UserSvc.Domain.Users;

/// <summary>
/// A consumer account. <b>Deliberately kept flat</b> (decision 04): it has no invariants worth
/// protecting in the domain layer — profile fields are CRUD, and the rules that do exist are
/// orchestrated by the application layer. The concepts that earn a rich model are the ones where
/// breaking an invariant is a security incident, such as <see cref="Auth.UserSession"/>.
/// <para>
/// It derives from <see cref="Entity"/> only so that it can carry domain events. That is not a
/// step towards a rich model: raising the event from the aggregate is what puts the outbox row in
/// the same transaction as the insert (decision 16), and an application service cannot do that -
/// the interceptor drains tracked entities, not services.
/// </para>
/// </summary>
public sealed class User : Entity
{
    public int Id { get; set; }

    public string Status { get; set; } = UserStatuses.Pending;

    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Nickname { get; set; } = string.Empty;
    public string Avatar { get; set; } = string.Empty;
    public string ResidenceCountryCode { get; set; } = string.Empty;

    /// <summary>Password hash algorithm (decision 13: legacy rows carry BCRYPT and are upgraded
    /// to ARGON2ID on the next successful sign-in).</summary>
    public string PasswordAlgo { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>Blind index: HMAC-SHA256(birth date, pepper). Enables exact match without
    /// storing the plaintext.</summary>
    public string BirthDateHash { get; set; } = string.Empty;
    /// <summary>Envelope-encrypted birth date (AES-256-GCM).</summary>
    public string BirthDateCiphertext { get; set; } = string.Empty;
    /// <summary>DEK version used to encrypt, so the rotation job can find rows to re-encrypt.</summary>
    public string BirthDateKeyVersion { get; set; } = string.Empty;

    public DateTimeOffset? LastLoginAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public string UpdatedBy { get; set; } = string.Empty;

    public List<UserIdentity> Identities { get; set; } = [];

    public bool IsActive() => Status == UserStatuses.Active;

    /// <summary>
    /// Records that this account was just created, so the fact reaches the outbox in the same
    /// transaction as the row itself. Called once, by registration, immediately before the insert.
    /// <para>
    /// The event carries the identity type and blind index rather than <see cref="Id"/> on purpose:
    /// the outbox row is serialized before the database assigns the key, so an id here would always
    /// publish 0.
    /// </para>
    /// </summary>
    public void RecordRegistration(string identityType, string identifierHash, DateTimeOffset now) =>
        Raise(new UserRegistered(identityType, identifierHash, now));

    /// <summary>
    /// Records that the person closed this account, so the fact reaches the outbox in the same
    /// transaction as the status change and the identity rows it releases.
    /// <para>
    /// Called once, by the deregistration use case, and only when the account was still active -
    /// re-running a completed deregistration must not publish a second event.
    /// </para>
    /// <para>
    /// The unbound identities are passed in rather than read from <see cref="Identities"/> because
    /// the caller has just decided which rows it is unbinding, and only the ones it actually
    /// changed belong in the event.
    /// </para>
    /// </summary>
    public void RecordDeregistration(IReadOnlyList<UnboundIdentity> unboundIdentities, DateTimeOffset now) =>
        Raise(new UserDeregistered(Id, unboundIdentities, now));
}
