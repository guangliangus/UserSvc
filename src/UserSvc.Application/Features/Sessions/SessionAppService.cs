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
    /// <summary>
    /// Read at the point of use, never in a field initializer or constructor (docs/architecture.md:
    /// "a missing capability may only break itself"). <c>IOptions.Value</c> is where
    /// DataAnnotations validation runs, so binding it into a field makes merely <i>constructing</i>
    /// this service throw - and this service is a constructor dependency of the token endpoint and
    /// of account deregistration, neither of which has anything to do with a session lifetime being
    /// out of range. <c>.Value</c> is cached, so reading it per use costs nothing.
    /// </summary>
    private AuthSessionOptions Options => options.Value;

    /// <summary>
    /// The signed-in devices of one subject, most recently seen first.
    /// <para>
    /// It takes a <see cref="SessionSubject"/> and not a user id because the two planes number
    /// their accounts independently: listing by id alone put back-office sessions on a consumer's
    /// devices screen, where signing one out revoked an operator's credential.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<DeviceSessionResponse>> ListDevicesAsync(
        SessionSubject subject,
        string currentSessionId,
        CancellationToken cancellationToken)
    {
        var active = await sessions.ListActiveBySubjectAsync(subject, cancellationToken);

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

        // The realm is stated by which entry point was called, not by an argument the caller might
        // omit: this one confirmed the subject against identity.users, so it is a consumer.
        await StartCoreAsync(
            SessionSubject.Consumer(userId), sessionId, authorizationId, device, cancellationToken);
    }

    /// <summary>
    /// Open a session for a <b>back-office</b> subject, whose status the sign-in flow has already
    /// established.
    /// <para>
    /// It exists because <see cref="StartAsync"/> confirms the subject through
    /// <c>IUserRepository</c>, which is the <i>consumer</i> account table. A back-office subject is
    /// an <c>iam.backend_users</c> id and the two planes number their accounts independently, so
    /// that lookup is wrong twice over: it answers "no such user" for every back-office id while
    /// <c>identity.users</c> is empty, and the day it is not, it would confirm one person's sign-in
    /// against a different person's row.
    /// </para>
    /// </summary>
    public Task StartForBackOfficeAsync(
        int userId,
        string sessionId,
        string authorizationId,
        DeviceDescriptor device,
        CancellationToken cancellationToken) =>
        StartCoreAsync(
            SessionSubject.BackOffice(userId), sessionId, authorizationId, device, cancellationToken);

    /// <summary>
    /// The session bookkeeping both planes share, once the caller has established that the subject
    /// may sign in. Neither plane's account table is touched from here.
    /// <para>
    /// <b>The realm arrives as part of the subject, and this is the seam that fixes it.</b> The two
    /// public entry points above are the only callers and each one knows which plane it speaks for,
    /// so the realm is decided where it is known rather than defaulted where it is not. Everything
    /// below - superseding the same device, and evicting past the device cap - reads only this
    /// subject's own realm, so a consumer signing in can no longer displace an operator who happens
    /// to share the integer.
    /// </para>
    /// </summary>
    private async Task StartCoreAsync(
        SessionSubject subject,
        string sessionId,
        string authorizationId,
        DeviceDescriptor device,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        var active = await sessions.ListActiveBySubjectAsync(subject, cancellationToken);

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
        if (remaining > Options.MaxActiveDevices)
        {
            var evicted = active
                .Except(displaced)
                .OrderBy(s => s.LastSeenAt)
                .Take(remaining - Options.MaxActiveDevices)
                .ToList();

            foreach (var session in evicted)
            {
                session.Revoke(RevocationReasons.DeviceLimit, now);
            }

            displaced.AddRange(evicted);
        }

        sessions.Add(UserSession.Start(sessionId, subject, device, authorizationId, now));
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
    /// <para>
    /// <b>No realm, on purpose.</b> The refresh request carries a <c>sid</c> and nothing else this
    /// method could scope by, and a <c>sid</c> is unique across the whole table for both planes.
    /// Deriving a realm here to add to the predicate would be inventing a second thing that can be
    /// wrong, and its failure mode - a live session reported dead - would sign the device out.
    /// </para>
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

    /// <summary>
    /// Sign one device out. Revoking an already-revoked session succeeds idempotently rather than
    /// returning 404.
    /// <para>
    /// The session is found by <c>sid</c>, which needs no realm, and the ownership check then
    /// compares the <b>whole</b> subject. Comparing ids alone meant an operator could sign out the
    /// consumer session that shared their id, and a consumer the operator's - a cross-plane
    /// revocation that looked, from either side, like signing out one's own device.
    /// </para>
    /// </summary>
    public async Task RevokeDeviceAsync(
        SessionSubject subject,
        string sessionId,
        string reason,
        CancellationToken cancellationToken)
    {
        var session = await sessions.FindBySessionIdAsync(sessionId, cancellationToken)
                      ?? throw new NotFoundException(ErrorCodes.SessionNotFound, "Session was not found.");

        // Somebody else's session answers 404, not 403 — otherwise the status-code difference lets a
        // caller probe whether a session exists. "Somebody else" includes the same id in the other
        // realm, which is a different person.
        if (!session.BelongsTo(subject))
        {
            throw new NotFoundException(ErrorCodes.SessionNotFound, "Session was not found.");
        }

        session.Revoke(reason, clock.UtcNow);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await tokenChains.RevokeChainAsync(session.AuthorizationId, cancellationToken);
        await revocationStore.RevokeAsync(sessionId, Options.AccessTokenLifetime, cancellationToken);
    }

    /// <summary>
    /// Sign every device of one subject out. Used on password change, on deregistration and on a
    /// detected leak.
    /// <para>
    /// Scoped to the subject's own realm. A sweep keyed on the id alone was the most damaging of
    /// the cross-realm reads: closing a consumer account would have signed an operator who shared
    /// the id out of the back office, with <c>DEREGISTERED</c> in the audit trail of a person who
    /// deregistered nothing.
    /// </para>
    /// </summary>
    public async Task RevokeAllAsync(
        SessionSubject subject,
        string reason,
        CancellationToken cancellationToken)
    {
        var active = await sessions.ListActiveBySubjectAsync(subject, cancellationToken);
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
                    session.SessionId, Options.AccessTokenLifetime, cancellationToken);
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
