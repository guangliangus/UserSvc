using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Auth;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Auth;

namespace UserSvc.Application.Features.Sessions;

/// <summary>
/// Device session use cases (decision 11). Revocation lands in two places: the database kills the
/// refresh path immediately, and the Redis revocation set kills <b>access tokens already issued</b>.
/// <para>
/// The order matters — commit to the database first, then write to Redis. The other way round, a
/// failed commit leaves "Redis says revoked, the database says alive": the user is signed out for
/// no visible reason and cannot recover. The failure mode of this order is "revoked in the
/// database, not written to Redis", which merely lets that device's access token live a few more
/// minutes; the refresh will still fail and the session will not come back.
/// </para>
/// </summary>
public sealed class SessionAppService(
    IUserSessionRepository sessions,
    ISessionRevocationStore revocationStore,
    IUnitOfWork unitOfWork,
    IClock clock,
    IOptions<AuthSessionOptions> options)
{
    private readonly AuthSessionOptions _options = options.Value;

    public async Task<IReadOnlyList<DeviceSessionResponse>> ListDevicesAsync(
        int userId,
        string currentSessionId,
        CancellationToken cancellationToken)
    {
        var active = await sessions.ListActiveByUserAsync(userId, cancellationToken);

        return [.. active
            .OrderByDescending(s => s.LastSeenAt)
            .Select(s => new DeviceSessionResponse
            {
                SessionId = s.SessionId,
                DeviceName = s.DeviceName,
                Platform = s.Platform,
                IpAddress = s.IpAddress,
                CreatedAt = s.CreatedAt,
                LastSeenAt = s.LastSeenAt,
                IsCurrent = s.SessionId == currentSessionId,
            })];
    }

    /// <summary>Sign one device out. Revoking an already-revoked session succeeds idempotently
    /// rather than returning 404.</summary>
    public async Task RevokeDeviceAsync(
        int userId,
        string sessionId,
        string reason,
        CancellationToken cancellationToken)
    {
        var session = await sessions.FindBySessionIdAsync(sessionId, cancellationToken)
                      ?? throw new NotFoundException(ErrorCodes.SessionNotFound, "Session was not found.");

        // Cross-user access answers 404, not 403 — otherwise the status-code difference lets a
        // caller probe whether a session exists.
        if (session.UserId != userId)
        {
            throw new NotFoundException(ErrorCodes.SessionNotFound, "Session was not found.");
        }

        session.Revoke(reason, clock.UtcNow);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await revocationStore.RevokeAsync(sessionId, _options.AccessTokenLifetime, cancellationToken);
    }

    /// <summary>Sign every device out. Used on password change and on a detected leak.</summary>
    public async Task RevokeAllAsync(int userId, string reason, CancellationToken cancellationToken)
    {
        var active = await sessions.ListActiveByUserAsync(userId, cancellationToken);
        if (active.Count == 0)
        {
            return;
        }

        var now = clock.UtcNow;
        foreach (var session in active)
        {
            session.Revoke(reason, now);
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);

        foreach (var session in active)
        {
            await revocationStore.RevokeAsync(session.SessionId, _options.AccessTokenLifetime, cancellationToken);
        }
    }

    /// <summary>
    /// Trade a refresh token for a new one. Three of the four outcomes are refusals; the actual
    /// decision lives in <see cref="UserSession.PresentRefreshToken"/> and this method only
    /// orchestrates and persists.
    /// </summary>
    public async Task<RefreshOutcome> RotateAsync(
        string presentedHash,
        string newHash,
        CancellationToken cancellationToken)
    {
        var session = await sessions.FindActiveByRefreshHashAsync(presentedHash, cancellationToken);
        if (session is null)
        {
            // No session holds this hash: either it never existed or it has already been rotated
            // away (a replay). Neither case gets a distinguishable response.
            throw new UnauthorizedException(ErrorCodes.InvalidToken, "Refresh token is not valid.");
        }

        var outcome = session.PresentRefreshToken(
            presentedHash, newHash, clock.UtcNow, _options.RefreshTokenLifetime);

        await unitOfWork.SaveChangesAsync(cancellationToken);

        if (outcome == RefreshOutcome.Replayed)
        {
            await revocationStore.RevokeAsync(
                session.SessionId, _options.AccessTokenLifetime, cancellationToken);
        }

        return outcome;
    }
}
