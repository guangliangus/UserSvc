using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.BackOffice;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// Machine-generated passwords, delivered through the notification capability service.
/// <para>
/// <b>This is an adaptation, not a second way out of the process.</b> The service already reaches
/// the notification centre through <see cref="INotificationClient"/> for verification codes, and a
/// separate HTTP client here would mean two resilience pipelines, two idempotency conventions and
/// two places to change when the upstream moves. What this class adds is the credential-specific
/// part: the two template names, the four variables they take, and the promise that a mail failure
/// is reported rather than thrown.
/// </para>
/// <para>
/// <b>Nothing here ever throws.</b> By the time it is called the account exists and the transaction
/// has committed; the recovery path is for an administrator to resend from the reset-password
/// action, and turning a mail outage into a 502 would hide the fact that the account was created.
/// The boolean is what tells the administrator to act - together with "the account was newly
/// created", a false is the one combination that needs somebody.
/// </para>
/// <para>
/// The password never reaches a log line, on any path. The address is masked, because a failure
/// line that quotes it turns the log into a directory.
/// </para>
/// </summary>
public sealed class NotificationCredentialEmailSender(
    INotificationClient notifications,
    IOptions<BackOfficeAccountOptions> options,
    ILogger<NotificationCredentialEmailSender> logger) : ICredentialEmailSender
{
    private const string InitialPasswordTemplate = "backend_initial_pwd_email";

    private const string PasswordResetTemplate = "backend_pwd_reset_email";

    public Task<bool> SendInitialPasswordAsync(
        int userId, string email, string displayName, string password, CancellationToken cancellationToken) =>
        SendAsync(InitialPasswordTemplate, userId, email, displayName, password, cancellationToken);

    public Task<bool> SendPasswordResetAsync(
        int userId, string email, string displayName, string password, CancellationToken cancellationToken) =>
        SendAsync(PasswordResetTemplate, userId, email, displayName, password, cancellationToken);

    private async Task<bool> SendAsync(
        string template,
        int userId,
        string email,
        string displayName,
        string password,
        CancellationToken cancellationToken)
    {
        var address = (email ?? string.Empty).Trim();
        if (address.Length == 0)
        {
            // Error, not warning: a password was generated and written, and there is no way to give
            // it to the person it belongs to. Somebody has to reset it once an address exists.
            logger.LogError(
                "A password was generated for back-office account {UserId}, but the account has no "
                + "e-mail address on file, so it could not be delivered.",
                userId);

            return false;
        }

        var loginUrl = options.Value.LoginUrl.Trim();
        if (loginUrl.Length == 0)
        {
            logger.LogError(
                "A password was generated for back-office account {UserId}, but BackOffice:LoginUrl "
                + "is not configured. It is a mandatory template variable, so the message would only "
                + "have failed upstream.",
                userId);

            return false;
        }

        var name = (displayName ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            name = BackOfficeNames.EmailLocalPart(address);
        }

        var request = new SendDirectRequest(
            template,
            [address],
            new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["display_name"] = name,
                ["account"] = address,
                ["password"] = password,
                ["login_path"] = loginUrl,
            },

            // A fresh key per call, not one derived from the account: the retry pipeline re-sends
            // this identical message and must be collapsed into one delivery, but an administrator
            // resending a reset an hour later is asking for a second mail and has to get one.
            $"{template}:{userId}:{Guid.NewGuid():N}");

        try
        {
            await notifications.SendDirectAsync(request, cancellationToken);
            return true;
        }
        catch (OperationCanceledException)
        {
            // The caller walked away. That is not a delivery failure to report as one.
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "The {Template} message for back-office account {UserId} ({MaskedEmail}) was not "
                + "accepted. The password is already in force; it has to be reset and resent.",
                template,
                userId,
                BackOfficeIdentifiers.Mask(BackendIdentityTypes.Email, address));

            return false;
        }
    }
}
