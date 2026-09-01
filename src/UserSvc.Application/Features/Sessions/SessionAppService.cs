using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Auth;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Domain.Auth;

namespace UserSvc.Application.Features.Sessions;

/// <summary>
/// Device session use cases (decision 11). Revocation lands in three places: the session row kills
/// our own refresh check immediately, <see cref="ITokenChainRevoker"/> kills the OpenIddict refresh
/// chain so the token stops being a credential at all, and the Redis revocation set kills
/// <b>access tokens already issued</b>.
/// <para>
/// The order matters — commit to the database first, then revoke the chain, then write to Redis.
/// The other way round, a failed commit leaves "Redis says revoked, the database says alive": the
/// user is signed out for no visible reason and cannot recover. The failure mode of this order is
/// "revoked in the database, not written to Redis", which merely lets that device's access token
/// live a few more minutes; the refresh will still fail and the session will not come back.
/// </para>
/// <para>
/// Rotation is <b>not</b> here any more: OpenIddict owns refresh tokens (decision 10). What is left
/// of the refresh path is <see cref="TryTouchAsync"/>, the check that turns a device sign-out into
/// an immediately dead refresh chain even before the chain revocation has been observed.
/// </para>
/// </summary>
public sealed class SessionAppService(
    IUserSessionRepository sessions,
    IUserRepository users,
    ISessionRevocationStore revocationStore,
    ITokenChainRevoker tokenChains,
    IUnitOfWork unitOfWork,
    IClock clock,
    IOptions<AuthSessionOptions> options,
    ILogger<SessionAppService> logger)
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

    /// <summary>
    /// Open a session for a device that has just signed in. The caller has already created the
    /// OpenIddict authorization, because the session row is worthless without the id that lets a
    /// later sign-out kill the token chain.
    /// <para>
    /// A second sign-in on the same device supersedes the previous session rather than sitting
    /// beside it — the partial unique index on (user_id, device_id) WHERE status = 'ACTIVE' would
    /// refuse the insert otherwise, and the old refresh chain would outlive the session it belongs
    /// to.
    /// </para>
    /// </summary>
    public async Task StartAsync(
        int userId,
        string sessionId,
        string authorizationId,
        DeviceDescriptor device,
        CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId, cancellationToken)
                   ?? throw new NotFoundException(ErrorCodes.UserNotFound, "User was not found.");

        if (!user.IsActive())
        {
            throw new ForbiddenException(ErrorCodes.AccountDisabled, "The account is not active.");
        }

        var now = clock.UtcNow;
        var active = await sessions.ListActiveByUserAsync(userId, cancellationToken);

        var displaced = active.Where(s => s.DeviceId == device.DeviceId).ToList();
        foreach (var previous in displaced)
        {
            previous.Revoke(RevocationReasons.Superseded, now);
        }

        // Enforce the active-device cap. Without this the row count per account grows without
        // bound: every reinstall reports a fresh device id, so nothing ever supersedes anything.
        // The least recently seen session gives way, which is what a "signed-in devices" screen
        // shows the user anyway.
        var remaining = active.Count - displaced.Count + 1;
        if (remaining > _options.MaxActiveDevices)
        {
            var evicted = active
                .Except(displaced)
                .OrderBy(s => s.LastSeenAt)
                .Take(remaining - _options.MaxActiveDevices)
                .ToList();

            foreach (var session in evicted)
            {
                session.Revoke(RevocationReasons.DeviceLimit, now);
            }

            displaced.AddRange(evicted);
        }

        sessions.Add(UserSession.Start(sessionId, userId, device, authorizationId, now));
        await unitOfWork.SaveChangesAsync(cancellationToken);

        // Best effort on purpose. The sessions above are already committed as revoked, so their
        // refresh chains are dead whatever happens next; failing the sign-in because a superseded
        // session's revocation entry could not be written would punish the wrong request.
        await PushRevocationsAsync(displaced, revokeChains: true, throwOnFailure: false, cancellationToken);
    }

    /// <summary>
    /// Confirm the session behind a refresh request is still alive and record that the device was
    /// seen. Returns <c>false</c> when the session is gone or revoked, which is how a sign-out on
    /// another device invalidates this refresh chain in the same second rather than whenever the
    /// revocation is noticed.
    /// </summary>
    public async Task<bool> TryTouchAsync(string sessionId, CancellationToken cancellationToken)
    {
        var session = await sessions.FindBySessionIdAsync(sessionId, cancellationToken);
        if (session is null || !session.IsActive)
        {
            return false;
        }

        session.Touch(clock.UtcNow);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return true;
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
        await tokenChains.RevokeChainAsync(session.AuthorizationId, cancellationToken);
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

        // Every session, then report. Aborting on the first failure would leave the remaining
        // devices holding usable access tokens for their full lifetime while their rows already
        // say REVOKED - the worst of both outcomes, and invisible.
        await PushRevocationsAsync(active, revokeChains: true, throwOnFailure: true, cancellationToken);
    }

    /// <summary>
    /// A redeemed refresh token was presented again. The detection belongs to OpenIddict, which is
    /// the only party holding the raw token and the token row; this method records the domain fact
    /// and takes the session down with it.
    /// <para>
    /// It deliberately does <b>not</b> call <see cref="ITokenChainRevoker"/>: OpenIddict revokes the
    /// whole authorization itself as part of rejecting the replay, and revoking it a second time
    /// from inside its own validation pipeline would only change the rejection reason it reports.
    /// </para>
    /// </summary>
    /// <returns>
    /// <c>false</c> when no session row carries this <c>sid</c>, so the caller can say so out loud.
    /// It is not a benign case: the replay is still refused, but the alert never reaches the outbox
    /// and nothing lands in the revocation set, so a leak that did happen leaves no trace.
    /// </returns>
    public async Task<bool> HandleRefreshTokenReplayAsync(string sessionId, CancellationToken cancellationToken)
    {
        var session = await sessions.FindBySessionIdAsync(sessionId, cancellationToken);
        if (session is null)
        {
            return false;
        }

        session.RevokeAsReplayed(clock.UtcNow);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        // Deliberately swallowed. This runs inside OpenIddict's validation pipeline, so an
        // UpstreamException here would answer the token endpoint with a 502 ProblemDetails instead
        // of the 400 invalid_grant every OAuth client expects. The security outcome does not depend
        // on it: the session row is already committed as REVOKED, so the chain is dead on refresh.
        // What is lost is only the fast path, for at most one access-token lifetime.
        await PushRevocationsAsync([session], revokeChains: false, throwOnFailure: false, cancellationToken);
        return true;
    }

    /// <summary>
    /// Push the post-commit side effects of a revocation: kill the OpenIddict chain, then record
    /// the session in the Redis revocation set so access tokens already issued stop working.
    /// <para>
    /// Every session is attempted even when an earlier one fails, because these are independent
    /// devices and a partial sweep is worse than a slow one. Whether the accumulated failure is
    /// then raised depends on who is asking: a user who pressed "sign out everywhere" should be
    /// told it did not fully take, while a sign-in superseding an old session, or OpenIddict
    /// rejecting a replay, must not have its own contract rewritten by a Redis outage.
    /// </para>
    /// </summary>
    private async Task PushRevocationsAsync(
        IReadOnlyList<UserSession> revoked,
        bool revokeChains,
        bool throwOnFailure,
        CancellationToken cancellationToken)
    {
        List<Exception>? failures = null;

        foreach (var session in revoked)
        {
            try
            {
                if (revokeChains)
                {
                    await tokenChains.RevokeChainAsync(session.AuthorizationId, cancellationToken);
                }

                await revocationStore.RevokeAsync(
                    session.SessionId, _options.AccessTokenLifetime, cancellationToken);
            }
            catch (AppException ex)
            {
                logger.LogError(
                    ex,
                    "Session {SessionId} is revoked in the database but its revocation could not be published; "
                    + "its access token stays usable for up to one token lifetime.",
                    session.SessionId);

                (failures ??= []).Add(ex);
            }
        }

        if (throwOnFailure && failures is not null)
        {
            throw new UpstreamException(
                ErrorCodes.UpstreamUnavailable,
                $"{failures.Count} of {revoked.Count} sessions were signed out in the database but "
                + "their revocations could not be published. Their access tokens remain usable "
                + "until they expire.",
                new AggregateException(failures));
        }
    }
}
