namespace UserSvc.Application.Ports.External;

/// <summary>
/// The notification service is a <b>capability service</b>: the single outbound path for SMS,
/// email and push (decision 01). The dividing line — this service owns "when to send, to whom,
/// and what it says"; that one owns "how it gets delivered". Switching SMS vendors, adding an
/// email channel, or moving from FCM to APNs must not reach into this codebase.
/// </summary>
public interface INotificationClient
{
    Task SendDirectAsync(SendDirectRequest request, CancellationToken cancellationToken);
}

/// <param name="Type">Template type, for example VERIFICATION_CODE.</param>
/// <param name="Recipients">Recipient identifiers; the notification service picks the channel.</param>
/// <param name="Variables">Template variables.</param>
/// <param name="IdempotencyKey">Retries will not send twice.</param>
public sealed record SendDirectRequest(
    string Type,
    IReadOnlyList<string> Recipients,
    IReadOnlyDictionary<string, object> Variables,
    string IdempotencyKey);
