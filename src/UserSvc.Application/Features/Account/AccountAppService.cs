using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Sessions;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Users;
using UserSvc.Domain.Users.Events;

namespace UserSvc.Application.Features.Account;

/// <summary>
/// Account deregistration - the one thing in this service a consumer can do to themselves that they
/// cannot undo.
/// <para>
/// <b>What it does not do is as deliberate as what it does.</b> Nothing is physically deleted. The
/// account row goes to DISABLED and every login identity goes with it; the profile, the feedback
/// the person filed and the audit trail of their sessions all stay exactly where they are. That is
/// the behaviour of the service being replaced, it is what the finance and support teams read
/// history out of, and turning it into a hard delete is a data-retention decision for the business,
/// not a detail of a port. What it is <i>not</i> is a GDPR erasure - if that is ever required it is
/// a separate, explicit flow, and the difference should not be blurred here.
/// </para>
/// <para>
/// <b>The identifiers become free again, and that is intended.</b> The unique index on
/// (identity_type, identifier_hash) covers ACTIVE rows only, so the moment an identity is disabled
/// the same phone number or mailbox may be registered - by this person starting over, or by whoever
/// inherits a recycled number. The alternative, keeping the identity bound to a dead account, means
/// someone who closes their account can never come back with the same number, and the person on the
/// other end of a recycled number is locked out of the product entirely.
/// </para>
/// </summary>
public sealed class AccountAppService(
    IUserRepository users,
    IUserIdentityRepository identities,
    SessionAppService sessions,
    IUnitOfWork unitOfWork,
    IClock clock,
    ILogger<AccountAppService> logger)
{
    /// <summary>
    /// Close the caller's own account.
    /// <para>
    /// <b>The order is the design, and it is the safe direction of an unavoidable non-atomicity.</b>
    /// Sessions die first, in their own committed step, and only then is the account disabled. Every
    /// way this can be interrupted therefore lands on "signed out but still registered", which the
    /// person can recover from by signing in and asking again. The other order lands on "deregistered
    /// but still signed in": nothing on the refresh path looks at the account's status - a refresh
    /// only asks whether the session row is alive - so a live session would keep minting access
    /// tokens for a closed account indefinitely, not until some expiry.
    /// </para>
    /// <para>
    /// <b>It is idempotent.</b> Re-running it on an already-disabled account changes no state and
    /// publishes no second event, but it does sweep the sessions again - which is exactly what a
    /// client retrying after the first attempt failed halfway needs it to do.
    /// </para>
    /// </summary>
    public async Task DeregisterAsync(int userId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId, cancellationToken)
                   ?? throw new NotFoundException(ErrorCodes.UserNotFound, "The account was not found.");

        // The id was just confirmed against identity.users, so the realm is a fact here rather
        // than an argument: the session sweep below must not reach the back-office session that
        // happens to share this integer, whose holder deregistered nothing.
        var subject = SessionSubject.Consumer(userId);

        // Three things at once, all of them immediate: the session rows become REVOKED so the next
        // refresh fails, the OpenIddict authorization behind each session is revoked so the refresh
        // token stops being a credential at all, and the Redis revocation set kills the access
        // tokens already in the wild. It raises on failure, and being raised here - before anything
        // about the account has changed - is the point: an account whose tokens could not be killed
        // must not be quietly closed while its holder keeps working.
        await sessions.RevokeAllAsync(subject, RevocationReasons.Deregistered, cancellationToken);

        if (user.Status == UserStatuses.Disabled)
        {
            logger.LogInformation(
                "Deregistration for account {UserId} found it already disabled; sessions were swept and nothing else changed.",
                userId);
            return;
        }

        var now = clock.UtcNow;
        var unbound = await identities.ListActiveByUserAsync(userId, cancellationToken);

        // Raised before the transaction body rather than inside it. ExecuteInTransactionAsync
        // replays its body when PostgreSQL reports a transient failure, and a raise inside would
        // add a second event on the replay - the first having already been drained into an outbox
        // row that is still tracked and still about to be inserted.
        user.RecordDeregistration(
            [.. unbound.Select(identity => new UnboundIdentity(identity.IdentityType, identity.IdentifierHash))],
            now);

        await unitOfWork.ExecuteInTransactionAsync(
            async token =>
            {
                foreach (var identity in unbound)
                {
                    identity.Status = UserStatuses.Disabled;
                    identity.UpdatedAt = now;
                }

                user.Status = UserStatuses.Disabled;
                user.UpdatedAt = now;

                // The outbox row lands in this same transaction (decision 16), so no consumer can
                // ever be told an account closed that then failed to close.
                await unitOfWork.SaveChangesAsync(token);
            },
            cancellationToken);

        logger.LogInformation(
            "Account {UserId} was deregistered; {IdentityCount} login identities were unbound and are available again.",
            userId,
            unbound.Count);

        // A second sweep, and not superstition. Between the first sweep and the commit above the
        // account was still ACTIVE, so a sign-in racing this request would have been allowed and its
        // session would outlive the account. The window is milliseconds and the sweep costs one
        // indexed query that normally returns nothing, which is a cheap price for not leaving a live
        // session on a closed account.
        await sessions.RevokeAllAsync(subject, RevocationReasons.Deregistered, cancellationToken);
    }
}
