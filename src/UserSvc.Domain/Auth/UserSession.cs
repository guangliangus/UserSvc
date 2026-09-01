using UserSvc.Domain.Abstractions;
using UserSvc.Domain.Auth.Events;

namespace UserSvc.Domain.Auth;

/// <summary>
/// One sign-in on one device: the session identity (<see cref="SessionId"/>, the <c>sid</c> claim),
/// the device metadata, the last-seen timestamp and revocation.
/// <para>
/// It is <b>narrower than it used to be</b> (decision 10). Refresh-token rotation and replay
/// detection now belong to OpenIddict, which owns the token rows and enforces single-use
/// rotation in the protocol layer where the raw token actually lives. Keeping a second, hand-rolled
/// rotation here would have meant two sources of truth for the same security promise, and the one
/// that silently drifted would have been ours.
/// </para>
/// <para>
/// What is left is still <b>deliberately rich</b> (decision 04): a revoked session must never come
/// back, and the reason of the <i>first</i> revocation is the one that gets audited. Those are
/// invariants whose violation is a security incident, so they are enforced here rather than
/// remembered by every caller.
/// </para>
/// </summary>
public sealed class UserSession : Entity
{
    public int Id { get; private set; }

    /// <summary>Goes into the access token's <c>sid</c> claim. Server-generated, and the only
    /// trustworthy session identifier.</summary>
    public string SessionId { get; private set; } = string.Empty;

    public int UserId { get; private set; }

    /// <summary>
    /// The OpenIddict authorization id every token issued for this session hangs off. Signing the
    /// device out revokes the session row <b>and</b> this whole token chain; without the id stored
    /// here, a sign-out would kill the session but leave a usable refresh token behind.
    /// </summary>
    public string AuthorizationId { get; private set; } = string.Empty;

    /// <summary>
    /// The client-reported <c>X-Device-ID</c>. <b>Not trustworthy</b> — used only for display and
    /// for replacing a previous session on the same device, never as a security boundary. The
    /// security boundary is <see cref="SessionId"/>.
    /// </summary>
    public string DeviceId { get; private set; } = string.Empty;

    public string DeviceName { get; private set; } = string.Empty;
    public string Platform { get; private set; } = string.Empty;
    public string AppVersion { get; private set; } = string.Empty;
    public string IpAddress { get; private set; } = string.Empty;
    public string UserAgent { get; private set; } = string.Empty;

    public string Status { get; private set; } = SessionStatuses.Active;
    public string RevokedBy { get; private set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset LastSeenAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }

    /// <summary>For EF.</summary>
    private UserSession()
    {
    }

    public bool IsActive => Status == SessionStatuses.Active;

    public static UserSession Start(
        string sessionId,
        int userId,
        DeviceDescriptor device,
        string authorizationId,
        DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            throw new DomainRuleException("SESSION_ID_REQUIRED", "Session id must be supplied by the server.");
        }

        // Not cosmetic: a session with no authorization id cannot have its token chain revoked, so
        // signing the device out would leave a working refresh token behind (decision 10).
        if (string.IsNullOrWhiteSpace(authorizationId))
        {
            throw new DomainRuleException(
                "AUTHORIZATION_ID_REQUIRED",
                "The OpenIddict authorization id is required so the token chain can be revoked.");
        }

        return new UserSession
        {
            SessionId = sessionId,
            UserId = userId,
            AuthorizationId = authorizationId,
            DeviceId = device.DeviceId,
            DeviceName = device.DeviceName,
            Platform = device.Platform,
            AppVersion = device.AppVersion,
            IpAddress = device.IpAddress,
            UserAgent = device.UserAgent,
            Status = SessionStatuses.Active,
            CreatedAt = now,
            LastSeenAt = now,
        };
    }

    /// <summary>
    /// Record that the device is still around. Called on token refresh only — writing on every
    /// request is write amplification for a column nobody reads that precisely.
    /// </summary>
    public void Touch(DateTimeOffset now)
    {
        if (!IsActive)
        {
            return;
        }

        LastSeenAt = now;
    }

    /// <summary>Revoke the session. Revoking an already-revoked session is a no-op, not an error.</summary>
    public void Revoke(string reason, DateTimeOffset now)
    {
        if (!IsActive)
        {
            return;
        }

        Status = SessionStatuses.Revoked;
        RevokedBy = reason;
        RevokedAt = now;
        Raise(new SessionRevoked(SessionId, UserId, reason, now));
    }

    /// <summary>
    /// A redeemed refresh token was presented again. <b>OpenIddict decides this, not the aggregate</b>
    /// (decision 10) — it is the only party that sees the raw token and the token row's status — but
    /// the alert is still a domain fact, and raising it here is what puts it in the outbox in the
    /// same transaction as the revocation (decision 16).
    /// </summary>
    public void RevokeAsReplayed(DateTimeOffset now)
    {
        Raise(new RefreshTokenReplayDetected(SessionId, UserId, DeviceId, now));
        Revoke(RevocationReasons.TokenReplay, now);
    }
}

/// <summary>Device details captured when a session starts. All client-reported, display only.</summary>
public sealed record DeviceDescriptor(
    string DeviceId,
    string DeviceName,
    string Platform,
    string AppVersion,
    string IpAddress,
    string UserAgent);
