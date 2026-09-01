using UserSvc.Domain.Abstractions;
using UserSvc.Domain.Auth.Events;

namespace UserSvc.Domain.Auth;

/// <summary>
/// One sign-in on one device: the session and its refresh-token family chain, which share a
/// lifetime.
/// <para>
/// This is one of the three <b>deliberately rich</b> concepts (decision 04). The test is not
/// "is this feature important" but "is a broken invariant here a security incident" — rotation
/// happens once, a replay means a leak, and a revoked session never comes back. Those rules in
/// the application layer would mean every caller has to remember to check; here, breaking them
/// means the code does not compile.
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

    /// <summary>SHA-256 of the currently valid refresh token. Presenting anything else is a replay.</summary>
    public string CurrentRefreshTokenHash { get; private set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset LastSeenAt { get; private set; }
    public DateTimeOffset RefreshExpiresAt { get; private set; }
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
        string refreshTokenHash,
        DateTimeOffset now,
        TimeSpan refreshLifetime)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            throw new DomainRuleException("SESSION_ID_REQUIRED", "Session id must be supplied by the server.");
        }

        if (string.IsNullOrWhiteSpace(refreshTokenHash))
        {
            throw new DomainRuleException("REFRESH_HASH_REQUIRED", "Refresh token hash is required.");
        }

        return new UserSession
        {
            SessionId = sessionId,
            UserId = userId,
            DeviceId = device.DeviceId,
            DeviceName = device.DeviceName,
            Platform = device.Platform,
            AppVersion = device.AppVersion,
            IpAddress = device.IpAddress,
            UserAgent = device.UserAgent,
            Status = SessionStatuses.Active,
            CurrentRefreshTokenHash = refreshTokenHash,
            CreatedAt = now,
            LastSeenAt = now,
            RefreshExpiresAt = now.Add(refreshLifetime),
        };
    }

    /// <summary>
    /// Trade a refresh token for a new one. This method is the reason the aggregate exists: three
    /// of its four outcomes are refusals, and <see cref="RefreshOutcome.Replayed"/> takes the whole
    /// chain down with it.
    /// </summary>
    public RefreshOutcome PresentRefreshToken(
        string presentedHash,
        string newHash,
        DateTimeOffset now,
        TimeSpan refreshLifetime)
    {
        if (!IsActive)
        {
            return RefreshOutcome.Revoked;
        }

        // Replay detection runs before the expiry check: a leaked old token means the chain is
        // already compromised, whether or not that token has expired.
        if (!FixedTimeEquals(presentedHash, CurrentRefreshTokenHash))
        {
            Raise(new RefreshTokenReplayDetected(SessionId, UserId, DeviceId, now));
            RevokeInternal(RevocationReasons.TokenReplay, now);
            return RefreshOutcome.Replayed;
        }

        if (now >= RefreshExpiresAt)
        {
            return RefreshOutcome.Expired;
        }

        CurrentRefreshTokenHash = newHash;
        RefreshExpiresAt = now.Add(refreshLifetime);
        LastSeenAt = now;   // Updated on refresh only; writing on every request is write amplification.
        return RefreshOutcome.Rotated;
    }

    /// <summary>Revoke the session. Revoking an already-revoked session is a no-op, not an error.</summary>
    public void Revoke(string reason, DateTimeOffset now)
    {
        if (!IsActive)
        {
            return;
        }

        RevokeInternal(reason, now);
    }

    private void RevokeInternal(string reason, DateTimeOffset now)
    {
        Status = SessionStatuses.Revoked;
        RevokedBy = reason;
        RevokedAt = now;
        CurrentRefreshTokenHash = string.Empty;
        Raise(new SessionRevoked(SessionId, UserId, reason, now));
    }

    /// <summary>Fixed-time comparison, so timing cannot be used to recover a hash prefix.</summary>
    private static bool FixedTimeEquals(string a, string b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        var diff = 0;
        for (var i = 0; i < a.Length; i++)
        {
            diff |= a[i] ^ b[i];
        }

        return diff == 0;
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
