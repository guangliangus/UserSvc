using UserSvc.Domain.Abstractions;

namespace UserSvc.Domain.Users.Events;

/// <summary>
/// An account was created and its first login identity bound.
/// <para>
/// <b>Business keys only, and the reason is mechanical.</b> The outbox row is written by the
/// SaveChanges interceptor, which runs <i>before</i> PostgreSQL assigns the identity column - so an
/// event carrying the new user's id would publish <c>0</c> to every consumer, with nothing to
/// signal that it had. The identity type and blind index identify the account just as precisely,
/// they are stable, and they leak no plaintext: the hash is the same value the unique index is
/// built on, so a consumer can join back to the row it describes.
/// </para>
/// </summary>
[EventName("user.registered.v1")]
public sealed record UserRegistered(
    string IdentityType,
    string IdentifierHash,
    DateTimeOffset OccurredAt) : IDomainEvent;
