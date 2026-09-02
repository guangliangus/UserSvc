using UserSvc.Application.Errors;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;

namespace UserSvc.Application.Features.BackOffice.Accounts;

/// <summary>
/// The one gate on the back-office self-service password reset: which targets it accepts, and which
/// accounts may go through it.
/// <para>
/// <b>It runs twice, at the two ends of one flow, and the two ends must not answer the same way.</b>
/// That is the reason it is a class rather than a private method, and the reason it has two entry
/// points over one rule. The verification module calls <see cref="EvaluateAsync"/> before mailing a
/// code, where the caller is a stranger: it takes the verdict and answers success either way, so
/// that a refusal tells nobody whether the address belongs to an operator (see the disclosure note
/// below). This feature calls <see cref="ResolveAsync"/> when the ticket is spent, where the caller
/// has just proved control of that mailbox and a refusal is owed to them as a real error - and
/// where the account may have been disabled in the minutes since the code went out. One rule, two
/// phrasings; two copies of the rule would eventually disagree, and the half that disagreed quietly
/// would be the one guarding the credential.
/// </para>
/// <para>
/// <b>Email only.</b> A phone number is refused rather than looked up: the back-office plane sends
/// reset codes to corporate mailboxes, and accepting a phone target would either find nothing - an
/// answer indistinguishable from "no such account" - or, worse, one day match a phone identity and
/// reset a password over a channel this flow was never designed around. That refusal is decided by
/// the shape of the string alone, so it is safe to state plainly at both ends.
/// </para>
/// <para>
/// <b>This gate answers a question that would be an account-existence oracle if it were spoken out
/// loud, so at the send-code end it is not.</b> An anonymous caller who could tell
/// <c>UNREGISTERED</c> from a code being sent would be able to map the operator directory one
/// corporate address at a time - and this plane has already paid to close exactly that oracle on
/// the password door, where an unknown mailbox and a wrong password answer identically and
/// <c>BackOfficePasswordTiming</c> spends a hash on the miss so that even the clock does not say
/// which it was. Answering <c>UNREGISTERED</c> here would hand all of that back
/// through a different endpoint about the same table. So the send step collapses
/// <see cref="BackOfficeResetEligibility.NoAccount"/> and
/// <see cref="BackOfficeResetEligibility.Disabled"/> into the same success answer it gives an
/// eligible address, and the discriminating error codes survive only at the submit step, where the
/// caller holds a ticket minted against that very mailbox. What remains disclosed there, and what
/// this does not close, is written up in docs/architecture.md under the enumeration-oracle table.
/// </para>
/// </summary>
public sealed class BackOfficeResetTargetGate(
    IBackendUserRepository users,
    IBackendIdentityRepository identities,
    IdentifierProtector protector)
{
    /// <summary>
    /// Resolves a reset target to the account it belongs to, or refuses in the caller's own terms.
    /// <para>
    /// For the <b>submit</b> end of the flow. The refusals name what happened because by this point
    /// the caller has spent a ticket that was minted against this mailbox, so they are the mailbox's
    /// owner and the answer is owed to them.
    /// </para>
    /// </summary>
    /// <param name="target">The address as the caller typed it. Normalized here, so callers must
    /// pass the raw value - the same string the verification ticket was minted against.</param>
    /// <param name="cancellationToken">Cancels the lookups.</param>
    /// <exception cref="BadRequestException">The target is not an email address, or no back-office
    /// account uses it.</exception>
    /// <exception cref="ForbiddenException">The account exists and is disabled. 403 rather than
    /// 400: the request is well formed and there is nothing the caller can change about it.</exception>
    public async Task<BackendUser> ResolveAsync(string target, CancellationToken cancellationToken)
    {
        var verdict = await EvaluateAsync(target, cancellationToken);

        return verdict.Eligibility switch
        {
            BackOfficeResetEligibility.Eligible => verdict.Account!,

            BackOfficeResetEligibility.Disabled => throw new ForbiddenException(
                ErrorCodes.AccountDisabled, "This back-office account is disabled."),

            _ => throw new BadRequestException(
                ErrorCodes.Unregistered, "That email address has no back-office account."),
        };
    }

    /// <summary>
    /// Answers whether this target could complete a reset, without deciding what the caller should
    /// be told.
    /// <para>
    /// For the <b>send-code</b> end of the flow, where the caller is anonymous. It returns a verdict
    /// rather than throwing for the two outcomes that would otherwise disclose whether a
    /// back-office account exists; the one refusal it still throws -
    /// <see cref="BadRequestException"/> for a target that is not an address - discloses nothing,
    /// because it is decided by the string and not by the database.
    /// </para>
    /// </summary>
    /// <param name="target">The address as the caller typed it, unnormalized.</param>
    /// <param name="cancellationToken">Cancels the lookups.</param>
    /// <exception cref="BadRequestException">The target is not an email address.</exception>
    public async Task<BackOfficeResetVerdict> EvaluateAsync(
        string target,
        CancellationToken cancellationToken)
    {
        if (!BackOfficeNames.IsEmail(target))
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest, "Back-office password reset supports email addresses only.");
        }

        var normalized = BackOfficeIdentifiers.Normalize(BackendIdentityTypes.Email, target);
        var masked = BackOfficeIdentifiers.Mask(BackendIdentityTypes.Email, normalized);

        var identity = await identities.FindActiveAsync(
            BackendIdentityTypes.Email, protector.Hash(normalized), cancellationToken);

        // A revoked identity reads as no identity at all, which is deliberate: the address is one
        // nobody can currently sign in with, and separating the two cases would be a distinction
        // only somebody probing the directory has a use for.
        if (identity is null)
        {
            return new BackOfficeResetVerdict(BackOfficeResetEligibility.NoAccount, masked, null);
        }

        var user = await users.FindByIdAsync(identity.UserId, cancellationToken);
        if (user is null)
        {
            // An identity whose account is gone. Reported as no account rather than as a fault,
            // because from the caller's side it is exactly that - there is nothing to reset.
            return new BackOfficeResetVerdict(BackOfficeResetEligibility.NoAccount, masked, null);
        }

        if (user.Status == BackendUserStatuses.Disabled)
        {
            return new BackOfficeResetVerdict(BackOfficeResetEligibility.Disabled, masked, user);
        }

        // PENDING deliberately passes. Such an account can sign in and hold nothing; letting it set
        // a password is how someone finishes onboarding, and refusing here would strand anyone
        // whose activation has not been approved yet.
        return new BackOfficeResetVerdict(BackOfficeResetEligibility.Eligible, masked, user);
    }
}

/// <summary>
/// What <see cref="BackOfficeResetTargetGate.EvaluateAsync"/> found. Three states rather than a
/// boolean, because the submit end owes a disabled account a different status code from an unknown
/// one - and because a caller that only needs "may this proceed" reads one member either way.
/// </summary>
public enum BackOfficeResetEligibility
{
    /// <summary>No active email identity, or none whose account still exists.</summary>
    NoAccount = 0,

    /// <summary>The account exists and is disabled.</summary>
    Disabled = 1,

    /// <summary>The account exists and may set a password. PENDING counts as eligible.</summary>
    Eligible = 2,
}

/// <summary>
/// The gate's finding about one target.
/// </summary>
/// <param name="Eligibility">Whether a reset could complete for this target.</param>
/// <param name="MaskedTarget">The normalized address masked for a log line - the only spelling of
/// it that may leave this service through a log, and the reason a caller does not have to reach for
/// a masking rule of its own.</param>
/// <param name="Account">The account, when one was found. Present for
/// <see cref="BackOfficeResetEligibility.Disabled"/> as well as for
/// <see cref="BackOfficeResetEligibility.Eligible"/>, and null otherwise.</param>
public sealed record BackOfficeResetVerdict(
    BackOfficeResetEligibility Eligibility,
    string MaskedTarget,
    BackendUser? Account);
