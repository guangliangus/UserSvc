using UserSvc.Domain.Abstractions;

namespace UserSvc.Domain.Auth.Events;

/// <summary>
/// A session was revoked. Consumers write <c>revoked:sid:{sid}</c> into the Redis revocation set
/// (decision 11: TTL equals the remaining access-token lifetime, which is why the set never grows).
/// </summary>
/// <param name="SessionId">The revoked session's <c>sid</c>.</param>
/// <param name="Realm">Which account table <paramref name="UserId"/> belongs to — one of
/// <see cref="SessionRealms"/>. Carried because the two realms number their accounts
/// independently: "session of user 100" names two different people without it, and this row is a
/// permanent security-audit record.</param>
/// <param name="UserId">The subject id within <paramref name="Realm"/>.</param>
/// <param name="Reason">One of <see cref="RevocationReasons"/>.</param>
/// <param name="OccurredAt">When the revocation happened.</param>
[EventName("user.session-revoked.v1")]
public sealed record SessionRevoked(
    string SessionId,
    string Realm,
    int UserId,
    string Reason,
    DateTimeOffset OccurredAt) : IDomainEvent;
