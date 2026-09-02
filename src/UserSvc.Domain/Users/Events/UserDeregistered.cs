using UserSvc.Domain.Abstractions;

namespace UserSvc.Domain.Users.Events;

/// <summary>
/// A consumer closed their own account. Every login identity it held has been unbound and the
/// account itself is disabled; both facts are already committed when this event is published.
/// <para>
/// <b>Business keys only, for the same mechanical reason as
/// <see cref="UserRegistered"/>.</b> The outbox row is serialized by the SaveChanges interceptor,
/// which runs before PostgreSQL has assigned anything - but unlike registration the account here
/// already has its id, so this event does carry it. What it must not carry is anything derived
/// from a row written in the same SaveChanges.
/// </para>
/// <para>
/// The unbound identities travel as <c>(type, blind index)</c> pairs, not as addresses: the hash is
/// the value the unique index is built on, so a consumer can match its own copy of the account
/// without this service ever putting a phone number or a mailbox on a message bus. That matters
/// most precisely here, where the subject has just asked to be forgotten.
/// </para>
/// <para>
/// <b>What a consumer should read into it:</b> the identifiers listed are free again. The partial
/// unique index only covers ACTIVE rows, so the same phone number may be registered by anyone -
/// including this person - from the moment this event is emitted.
/// </para>
/// </summary>
[EventName("user.deregistered.v1")]
public sealed record UserDeregistered(
    int UserId,
    IReadOnlyList<UnboundIdentity> UnboundIdentities,
    DateTimeOffset OccurredAt) : IDomainEvent;

/// <summary>One login identity released by a deregistration, named the way the unique index names
/// it.</summary>
public sealed record UnboundIdentity(string IdentityType, string IdentifierHash);
