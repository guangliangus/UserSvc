namespace UserSvc.Application.Ports.Verification;

/// <summary>
/// Spending the proof that someone controls a phone number or a mailbox.
/// <para>
/// It is a separate, one-method port on purpose. Registration, password reset and binding need
/// exactly this and nothing else - they have no business being able to issue codes or read the
/// send history - and a narrow port is also a narrow test double: those slices substitute one
/// method rather than a repository whose other members they must remember to leave alone.
/// </para>
/// <para>
/// <b>Callers must invoke it inside their own transaction.</b> Consuming the ticket is the moment
/// the proof is spent; if it commits and the work it authorised then fails, the user is left
/// holding a dead ticket and has to walk the whole code flow again.
/// </para>
/// </summary>
public interface IVerificationTicketConsumer
{
    /// <summary>
    /// Burn the ticket, if it is real. The ticket must exist, have been verified, not have been
    /// spent, not have expired, and have been minted for this exact target <b>and</b> purpose -
    /// the purpose is what stops a ticket issued to reset a consumer password from creating a
    /// back-office account.
    /// <para>
    /// Returns <see langword="false"/> rather than throwing, because every caller wants to phrase
    /// the refusal in terms of its own flow, and because there is nothing here to distinguish: a
    /// ticket that is unknown, spent or expired is one and the same "no" to the caller, and saying
    /// which would tell an attacker whether they had guessed a real ticket.
    /// </para>
    /// </summary>
    Task<bool> TryConsumeAsync(
        string target,
        string purpose,
        string ticket,
        CancellationToken cancellationToken);
}
