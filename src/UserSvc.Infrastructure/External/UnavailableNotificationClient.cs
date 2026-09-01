using UserSvc.Application.Ports.External;
using UserSvc.Application.Errors;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// <b>Placeholder</b>: the real HTTP client for the notification service arrives in stage 2.
/// <para>
/// Following the rule that a placeholder picks the safe side, this one fails rather than pretends
/// to succeed. Pretending would let callers believe a verification code went out; the user would
/// wait forever and see no error. Failing is at least an honest state that monitoring can see.
/// </para>
/// </summary>
public sealed class UnavailableNotificationClient : INotificationClient
{
    public Task SendDirectAsync(SendDirectRequest request, CancellationToken cancellationToken) =>
        throw new UpstreamException(
            ErrorCodes.UpstreamUnavailable,
            "The notification service client is not wired yet (placeholder implementation).");
}
