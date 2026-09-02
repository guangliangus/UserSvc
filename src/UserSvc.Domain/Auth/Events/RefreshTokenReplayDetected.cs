using UserSvc.Domain.Abstractions;

namespace UserSvc.Domain.Auth.Events;

/// <summary>
/// An already-rotated refresh token was presented again — the only plausible explanation is that
/// the token leaked. This is a security alert, not just an audit record.
/// </summary>
/// <param name="SessionId">The session whose refresh chain was replayed.</param>
/// <param name="Realm">Which account table <paramref name="UserId"/> belongs to — one of
/// <see cref="SessionRealms"/>. Without it the alert names an id that exists in two planes, and an
/// alert nobody can attribute is an alert nobody acts on.</param>
/// <param name="UserId">The subject id within <paramref name="Realm"/>.</param>
/// <param name="DeviceId">The client-reported device the replay arrived from.</param>
/// <param name="OccurredAt">When the replay was detected.</param>
[EventName("user.refresh-token-replayed.v1")]
public sealed record RefreshTokenReplayDetected(
    string SessionId,
    string Realm,
    int UserId,
    string DeviceId,
    DateTimeOffset OccurredAt) : IDomainEvent;
