using UserSvc.Domain.Abstractions;

namespace UserSvc.Domain.Auth.Events;

/// <summary>
/// A session was revoked. Consumers write <c>revoked:sid:{sid}</c> into the Redis revocation set
/// (decision 11: TTL equals the remaining access-token lifetime, which is why the set never grows).
/// </summary>
[EventName("user.session-revoked.v1")]
public sealed record SessionRevoked(
    string SessionId,
    int UserId,
    string Reason,
    DateTimeOffset OccurredAt) : IDomainEvent;
