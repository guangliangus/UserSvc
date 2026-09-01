using UserSvc.Domain.Abstractions;

namespace UserSvc.Domain.Auth.Events;

/// <summary>
/// An already-rotated refresh token was presented again — the only plausible explanation is that
/// the token leaked. This is a security alert, not just an audit record.
/// </summary>
[EventName("user.refresh-token-replayed.v1")]
public sealed record RefreshTokenReplayDetected(
    string SessionId,
    int UserId,
    string DeviceId,
    DateTimeOffset OccurredAt) : IDomainEvent;
