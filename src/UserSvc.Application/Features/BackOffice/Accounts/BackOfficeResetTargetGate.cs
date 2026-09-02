using UserSvc.Application.Errors;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;

namespace UserSvc.Application.Features.BackOffice.Accounts;

/// <summary>
/// The one gate on the back-office self-service password reset: which targets it accepts, and which
/// accounts may go through it.
/// <para>
/// <b>It runs twice on purpose</b>, and that is the reason it is a class rather than a private
/// method. The verification module runs it before mailing a code, so nobody receives a code for a
/// mailbox that could not reset anything anyway; this feature runs it again when the ticket is
/// spent, because an account can be disabled in the minutes between the code being sent and the
/// reset being submitted, and only the second run happens after that decision. Two copies of the
/// rule would eventually disagree, and the half that disagreed quietly would be the one guarding
/// the credential.
/// </para>
/// <para>
/// <b>Email only.</b> A phone number is refused rather than looked up: the back-office plane sends
/// reset codes to corporate mailboxes, and accepting a phone target would either find nothing - an
/// answer indistinguishable from "no such account" - or, worse, one day match a phone identity and
/// reset a password over a channel this flow was never designed around.
/// </para>
/// <para>
/// <b>This gate is an account-existence oracle and is known to be one.</b> An unregistered address
/// answers <c>UNREGISTERED</c> while a registered one gets a code, so a patient caller can map the
/// back office one address at a time. It is kept because the consumer reset flow answers exactly
/// the same way and the clients branch on it; closing it means one uniform "if that address is
/// registered, a code is on its way" answer across both planes, which is a contract change for
/// every client rather than something this slice can flip on its own. The IP budget in front of the
/// send-code endpoint is what stands between that oracle and a scraped directory.
/// </para>
/// </summary>
public sealed class BackOfficeResetTargetGate(
    IBackendUserRepository users,
    IBackendIdentityRepository identities,
    IdentifierProtector protector)
{
    /// <summary>
    /// Resolves a reset target to the account it belongs to, or refuses.
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
        if (!BackOfficeNames.IsEmail(target))
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest, "Back-office password reset supports email addresses only.");
        }

        var normalized = BackOfficeIdentifiers.Normalize(BackendIdentityTypes.Email, target);
        var identity = await identities.FindActiveAsync(
            BackendIdentityTypes.Email, protector.Hash(normalized), cancellationToken);

        // A revoked identity reads as no identity at all, which is deliberate: the address is one
        // nobody can currently sign in with, and saying so in a distinct way would tell a stranger
        // that an account exists behind it.
        if (identity is null)
        {
            throw new BadRequestException(
                ErrorCodes.Unregistered, "That email address has no back-office account.");
        }

        var user = await users.FindByIdAsync(identity.UserId, cancellationToken);
        if (user is null)
        {
            // An identity whose account is gone. Reported as unregistered rather than as a fault,
            // because from the caller's side it is exactly that - there is no account to reset.
            throw new BadRequestException(
                ErrorCodes.Unregistered, "That email address has no back-office account.");
        }

        if (user.Status == BackendUserStatuses.Disabled)
        {
            throw new ForbiddenException(
                ErrorCodes.AccountDisabled, "This back-office account is disabled.");
        }

        // PENDING deliberately passes. Such an account can sign in and hold nothing; letting it set
        // a password is how someone finishes onboarding, and refusing here would strand anyone
        // whose activation has not been approved yet.
        return user;
    }
}
