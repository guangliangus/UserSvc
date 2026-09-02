using System.Net.Http.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Polly;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.External;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The HTTP adapter for the notification capability service (decision 01).
/// <para>
/// There is no retry loop, no backoff and no timeout logic in this class. All of it lives in the
/// standard resilience handler configured in <c>DependencyInjection</c>, so what is left here is
/// exactly one job: turn a transport outcome into the error contract (decision 09).
/// </para>
/// <para>
/// <b>The 5xx/4xx split is the point of this class, and it is deliberate.</b> A 5xx, a connection
/// failure or an exhausted timeout means the notification service is down or overloaded - nothing
/// about our request was wrong - so it becomes <see cref="UpstreamException"/> (502) and both the
/// caller and the dashboard point at the upstream. A 4xx says the opposite: the notification
/// service understood the request and refused it, which makes it <b>our</b> defect - an unknown
/// template type, a malformed recipient, a missing variable. Reporting that as 502 would blame a
/// service that is working perfectly and send the page to the wrong on-call, so it is mapped to a
/// 500-class failure instead. 408 and 429 are the exceptions inside the 4xx range: both mean
/// "come back later", not "you sent nonsense", and they are treated as upstream faults.
/// </para>
/// <para>
/// The rejection body is the only thing that names the offending field, and it goes to the
/// <b>log only</b>. It is text written by another service and can quote recipient identifiers, so
/// it must never travel back through an exception message - <see cref="AppException"/> messages
/// are rendered into the response body verbatim.
/// </para>
/// </summary>
public sealed class NotificationHttpClient(
    HttpClient httpClient,
    IOptions<NotificationOptions> options,
    ILogger<NotificationHttpClient> logger) : INotificationClient
{
    private const string IdempotencyKeyHeader = "Idempotency-Key";

    /// <summary>Enough of a rejection body to identify the bad field; a runaway upstream error page is not a log entry.</summary>
    private const int MaxLoggedBodyLength = 2048;

    /// <summary>Long enough for a GUID, a ULID or a prefixed composite; short enough that no header limit is at risk.</summary>
    private const int MaxIdempotencyKeyLength = 255;

    private const string UpstreamUnavailableMessage =
        "The notification could not be sent because the notification service is unavailable.";

    /// <summary>
    /// The validated section, read at the point of use and never in a field initializer.
    /// <para>
    /// A field initializer runs in the constructor, and <see cref="IOptions{TOptions}.Value"/> is
    /// where DataAnnotations validation happens - so reading it there makes merely
    /// <i>constructing</i> this class throw, taking down every caller that has this one in its
    /// dependency graph rather than only the capability whose configuration is missing. That is
    /// the failure docs/architecture.md records, and it stays fixed here even though this section
    /// is validated at startup today: the shape must not be lying around for the day somebody
    /// removes <c>ValidateOnStart</c> from it, which has already happened to four sections in this
    /// service. <see cref="IOptions{TOptions}.Value"/> caches, so a property costs nothing.
    /// </para>
    /// </summary>
    private string _sendDirectPath => options.Value.SendDirectPath;

    public async Task SendDirectAsync(SendDirectRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireUsableIdempotencyKey(request);

        // The resilience handler re-sends this same HttpRequestMessage on every attempt. That is
        // what makes the retry safe: the Idempotency-Key is byte-identical across attempts, so the
        // notification service collapses them into one send. It also means the content must be
        // re-readable - JsonContent is, StreamContent would fail on the second attempt.
        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, _sendDirectPath)
        {
            Content = JsonContent.Create(request),
        };

        httpRequest.Headers.TryAddWithoutValidation(IdempotencyKeyHeader, request.IdempotencyKey);

        // Disposed on every path below, success and failure alike.
        using var response = await SendAsync(httpRequest, request, cancellationToken).ConfigureAwait(false);

        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var status = (int)response.StatusCode;
        var body = await ReadBodyForLogAsync(response, cancellationToken).ConfigureAwait(false);

        if (status >= 500 || status is 408 or 429)
        {
            logger.LogError(
                "Notification service answered {StatusCode} for {NotificationType} " +
                "(idempotency key {IdempotencyKey}). Upstream body: {ResponseBody}",
                status,
                request.Type,
                request.IdempotencyKey,
                body);

            throw new UpstreamException(ErrorCodes.UpstreamUnavailable, UpstreamUnavailableMessage);
        }

        logger.LogError(
            "Notification service rejected {NotificationType} with {StatusCode} " +
            "(idempotency key {IdempotencyKey}). A 4xx here is our bug, not theirs - the payload " +
            "we sent is wrong. Upstream body: {ResponseBody}",
            request.Type,
            status,
            request.IdempotencyKey,
            body);

        // 500, not 502: the upstream is healthy and said no. The body stays in the log above.
        throw new AppException(
            ErrorCodes.InternalError,
            "The notification could not be sent.",
            500);
    }

    /// <summary>
    /// Checked before anything is sent, because the key is the only thing standing between one
    /// verification code and three: the retry strategy re-sends the identical message and the
    /// upstream deduplicates on this header alone.
    /// <para>
    /// <c>TryAddWithoutValidation</c> inspects the header <i>name</i> only - the name here is a
    /// constant, so it always returns true and the value is never looked at. A blank key would
    /// therefore ship a header nothing can deduplicate on, and a CR or LF would be written into the
    /// request message verbatim. Both are defects in the calling code, so they fail loudly here as
    /// <see cref="ArgumentException"/> (500 INTERNAL_ERROR, message kept out of the response body)
    /// rather than as duplicate SMS or a mangled request on the wire.
    /// </para>
    /// </summary>
    private static void RequireUsableIdempotencyKey(SendDirectRequest request)
    {
        var key = request.IdempotencyKey;

        if (string.IsNullOrWhiteSpace(key) || key.Length > MaxIdempotencyKeyLength)
        {
            throw new ArgumentException(
                $"{nameof(SendDirectRequest.IdempotencyKey)} must be non-blank and at most "
                + $"{MaxIdempotencyKeyLength} characters; retries deduplicate on it.",
                nameof(request));
        }

        foreach (var character in key)
        {
            if (!char.IsAscii(character) || char.IsControl(character))
            {
                throw new ArgumentException(
                    $"{nameof(SendDirectRequest.IdempotencyKey)} must be printable ASCII; a control "
                    + "character would be written into the request headers unvalidated.",
                    nameof(request));
            }
        }
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage httpRequest,
        SendDirectRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            return await httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw Unreachable(request, ex);
        }
        catch (ExecutionRejectedException ex)
        {
            // The pipeline's own verdict: the total-request timeout elapsed, the circuit is open,
            // or the concurrency limiter shed the call. All three mean nobody answered. None of
            // them derives from OperationCanceledException, so the catch below would not see them.
            throw Unreachable(request, ex);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            // A timeout that surfaced as cancellation instead of a rejection. The filter is what
            // keeps a caller-initiated cancellation propagating as cancellation rather than being
            // reported as an upstream outage.
            throw Unreachable(request, ex);
        }
    }

    private UpstreamException Unreachable(SendDirectRequest request, Exception cause)
    {
        // Recipients are personal data and are deliberately absent from this line; the idempotency
        // key is what correlates it with the notification service's own logs.
        logger.LogError(
            cause,
            "Notification service is unreachable for {NotificationType} (idempotency key {IdempotencyKey}).",
            request.Type,
            request.IdempotencyKey);

        return new UpstreamException(ErrorCodes.UpstreamUnavailable, UpstreamUnavailableMessage, cause);
    }

    /// <summary>
    /// Diagnostics only, and it must never fail the caller: by the time this runs the send has
    /// already failed and the status code is the diagnosis. If the caller cancels in this window
    /// the upstream failure still wins - the response is in hand, so reporting it beats reporting
    /// the cancellation.
    /// </summary>
    private static async Task<string> ReadBodyForLogAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        try
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return body.Length <= MaxLoggedBodyLength ? body : body[..MaxLoggedBodyLength];
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or InvalidOperationException)
        {
            return "<unreadable: " + ex.GetType().Name + ">";
        }
    }
}
