namespace UserSvc.Application.Ports.Tenancy;

/// <summary>
/// Delivery of machine-generated passwords.
/// <para>
/// Two properties are load-bearing and neither is obvious from the signatures. It must be called
/// <b>after the transaction commits</b> - sending from inside would hold a tenant advisory lock
/// across an HTTP call, and could post credentials for an account a rollback then un-created. And
/// it must <b>never</b> fail the request: the account already exists, the recovery path is to
/// resend from the reset-password action, and turning a mail outage into a 502 would only hide
/// that fact.
/// </para>
/// </summary>
public interface ICredentialEmailSender
{
    /// <returns>Whether the message was accepted. False is reported to the administrator rather
    /// than thrown - together with "the account was newly created", it is the one combination that
    /// needs somebody to act.</returns>
    Task<bool> SendInitialPasswordAsync(
        int userId, string email, string displayName, string password, CancellationToken cancellationToken);

    Task<bool> SendPasswordResetAsync(
        int userId, string email, string displayName, string password, CancellationToken cancellationToken);
}
