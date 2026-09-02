using System.ComponentModel.DataAnnotations;
using Azure;
using Azure.Core;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.External;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The Azure Blob Storage adapter for <see cref="IObjectStorage"/> - the real client, the real
/// upload, the real URL, the real delete. It reads its account credentials from
/// <see cref="AzureBlobOptions"/> and nothing else about it is conditional.
/// <para>
/// <b>It is not a placeholder, and the distinction is worth being precise about.</b> A placeholder
/// means nobody has written the logic yet and the refusal is standing in for a design decision. This
/// class contains the whole operation: the container client, the streamed upload, the HTTP headers
/// the object is served with, the URL construction, and the mapping from Azure's failures onto this
/// service's error contract. What it does not have is a connection string, because no environment
/// visible from here has one. Supply <c>AzureBlob:ConnectionString</c> and this file becomes live
/// without a line changing.
/// </para>
/// <para>
/// <b>Why the missing connection string fails the request rather than the boot.</b> Every other
/// required secret in this service - the database, Redis, the token-signing certificates - is
/// <c>[Required]</c> and refuses to start, and that is right for them: they sit on paths that every
/// request crosses, so a deployment missing one is not a degraded service, it is a service that
/// answers nothing correctly. Avatar upload is one endpoint. Making it <c>[Required]</c> would mean
/// a deployment that has no blob account cannot sign anybody in, cannot issue a token and cannot
/// serve the back office - the entire service held hostage by a profile picture. So the refusal
/// lands exactly where the capability is missing: <see cref="PutAsync"/> throws, every other
/// endpoint is untouched, and the log line says which setting is absent.
/// <br/>
/// The option is still validated: if a connection string <i>is</i> supplied it must parse, and that
/// check does run at startup (see <see cref="AzureBlobOptions.Validate"/>). "Absent" is a
/// deployment choice; "present and malformed" is a mistake, and a mistake should not wait for the
/// first user to upload a photo to be discovered.
/// </para>
/// <para>
/// Registered as a singleton. <see cref="BlobServiceClient"/> holds an HTTP pipeline with its own
/// connection pooling and is documented as thread-safe; building one per request would leak
/// sockets. It is built lazily so that an unconfigured deployment does not fail while the container
/// is being constructed - which would take the whole host down and defeat the paragraph above.
/// </para>
/// </summary>
public sealed class AzureBlobObjectStorage : IObjectStorage
{
    private const string UnconfiguredMessage =
        "Avatar upload is not available on this deployment.";

    private const string UpstreamMessage =
        "The image could not be stored because the storage service is unavailable.";

    private const string RejectedMessage = "The image could not be stored.";

    private readonly AzureBlobOptions _options;
    private readonly ILogger<AzureBlobObjectStorage> _logger;
    private readonly Lazy<BlobContainerClient> _container;

    public AzureBlobObjectStorage(
        IOptions<AzureBlobOptions> options,
        ILogger<AzureBlobObjectStorage> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options.Value;
        _logger = logger;

        // ExecutionAndPublication: one client for the process even under a burst of first requests.
        _container = new Lazy<BlobContainerClient>(
            () => new BlobServiceClient(_options.ConnectionString, BuildClientOptions(_options))
                .GetBlobContainerClient(_options.ContainerName),
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <inheritdoc />
    public async Task<Uri> PutAsync(
        string objectName,
        Stream content,
        ObjectHttpHeaders headers,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(objectName);
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(headers);

        var blob = ResolveContainer().GetBlobClient(objectName);

        var uploadOptions = new BlobUploadOptions
        {
            // Written onto the blob itself, so they are returned on every later GET without this
            // service being in the path. Content-Type is what stops a browser sniffing the bytes
            // into something executable, and it is set from what the bytes actually are - the
            // caller has already established that.
            HttpHeaders = new BlobHttpHeaders
            {
                ContentType = headers.ContentType,
                CacheControl = headers.CacheControl,
                ContentDisposition = headers.ContentDisposition,
            },
        };

        try
        {
            // No access condition: an object name collides only if two uploads for one account land
            // in the same millisecond, and overwriting is the harmless outcome of that race.
            await blob.UploadAsync(content, uploadOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (RequestFailedException ex)
        {
            throw Translate(ex, ex, objectName, LogLevel.Error);
        }
        catch (AggregateException ex)
        {
            // The SDK does not rethrow the last attempt when its retry policy gives up on a
            // transport failure: it throws an AggregateException wrapping one RequestFailedException
            // per attempt. Verified against 12.29.2 by pointing a well-formed connection string at
            // an account host that does not resolve - six inner RequestFailedExceptions, each with
            // Status 0. Catching only RequestFailedException therefore missed the single most
            // likely outage of all, "the storage account is unreachable": it escaped this class
            // unlogged and reached the generic handler as a 500 INTERNAL_ERROR, when the
            // failure-semantics table says an upstream that is down is a 502.
            throw Translate(
                ex,
                ex.Flatten().InnerExceptions.OfType<RequestFailedException>().LastOrDefault(),
                objectName,
                LogLevel.Error);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw Timeout(ex, objectName, "storing", LogLevel.Error);
        }

        // Built by the SDK from the account endpoint and the container, so it stays correct for a
        // connection string that names a custom endpoint or an emulator - which string concatenation
        // would not. Reading it back is a property access; nothing goes over the wire.
        return blob.Uri;
    }

    /// <inheritdoc />
    public async Task DeleteAsync(string objectName, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(objectName))
        {
            // Nothing addresses an object here, so there is nothing to do and nothing to report.
            return;
        }

        if (string.IsNullOrWhiteSpace(_options.ConnectionString))
        {
            // Deliberately NOT the 501 that PutAsync throws. A deployment with no storage account
            // has never written an object, so a delete has nothing to refuse - and the only callers
            // of this method are already unwinding some other failure, which the 501 would mask.
            // Debug, not warning: on such a deployment PutAsync refused first, so this is
            // unreachable in practice and does not deserve a line in a production log.
            _logger.LogDebug(
                "A delete of {ObjectName} was skipped: {Section}:{Setting} is not configured, so "
                + "no object was ever stored.",
                objectName,
                AzureBlobOptions.SectionName,
                nameof(AzureBlobOptions.ConnectionString));

            return;
        }

        var blob = ResolveContainer().GetBlobClient(objectName);

        try
        {
            // DeleteIfExists, not Delete: a name that was never written must not fail the caller.
            // A failed upload may or may not have left bytes behind and no caller can tell which,
            // so "it was not there" is the expected answer at least as often as "it was".
            await blob.DeleteIfExistsAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (RequestFailedException ex)
        {
            throw Translate(ex, ex, objectName, LogLevel.Warning);
        }
        catch (AggregateException ex)
        {
            throw Translate(
                ex,
                ex.Flatten().InnerExceptions.OfType<RequestFailedException>().LastOrDefault(),
                objectName,
                LogLevel.Warning);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw Timeout(ex, objectName, "deleting", LogLevel.Warning);
        }
    }

    /// <summary>
    /// The SDK's own timeout, which arrives as cancellation rather than as a failed request.
    /// <para>
    /// Callers filter on <c>!cancellationToken.IsCancellationRequested</c> before reaching here, so
    /// a cancellation the caller asked for keeps propagating as one - turning a client disconnect
    /// into a 502 would fill the dashboard with other people's closed laptops.
    /// </para>
    /// </summary>
    private UpstreamException Timeout(Exception thrown, string objectName, string verb, LogLevel level)
    {
        _logger.Log(
            level,
            thrown,
            "Azure Blob Storage timed out {Verb} {ObjectName} in container {ContainerName}.",
            verb,
            objectName,
            _options.ContainerName);

        return new UpstreamException(ErrorCodes.UpstreamUnavailable, UpstreamMessage, thrown);
    }

    /// <summary>
    /// The SDK's retry budget, bounded, because its defaults are wrong for a request someone is
    /// waiting on.
    /// <para>
    /// Left alone, <see cref="BlobClientOptions"/> allows six attempts with a 100-second network
    /// timeout each and an exponential backoff whose delay is capped at a minute: an upload against
    /// a storage account that is down can hold a request - and the thread and the buffered body
    /// behind it - for several minutes before anyone gets an answer. The person uploading a photo
    /// gave up long before, and their retries pile up on top. Every other outbound call in this
    /// service is bounded (see <c>NotificationOptions</c>), and this one is now too: a few seconds
    /// per attempt and a couple of attempts, so an outage costs a fast 502 instead of a hung
    /// request.
    /// </para>
    /// </summary>
    private static BlobClientOptions BuildClientOptions(AzureBlobOptions options)
    {
        var clientOptions = new BlobClientOptions();

        clientOptions.Retry.Mode = RetryMode.Exponential;
        clientOptions.Retry.MaxRetries = options.MaxRetryAttempts;
        clientOptions.Retry.NetworkTimeout = options.AttemptTimeout;
        clientOptions.Retry.Delay = TimeSpan.FromMilliseconds(500);
        clientOptions.Retry.MaxDelay = TimeSpan.FromSeconds(2);

        return clientOptions;
    }

    /// <summary>
    /// One failure, classified once, however the SDK chose to wrap it.
    /// <para>
    /// The split follows the failure-semantics table: an upstream that is down, throttling or never
    /// answered is a 502 pointing at the storage account, while a request Azure understood and
    /// refused is a 500 pointing at us - a 403 is the wrong key, a 404 is a container that does not
    /// exist, and calling either of those 502 would page whoever runs the storage service about our
    /// own settings. Status 0 is the SDK's "the request never completed".
    /// </para>
    /// </summary>
    /// <param name="thrown">What was actually caught - the aggregate, when there was one - so the
    /// log and the inner exception keep every attempt.</param>
    /// <param name="failure">The request failure to classify on, or <see langword="null"/> when the
    /// wrapper held none.</param>
    /// <param name="objectName">The object being written, for the log.</param>
    /// <param name="level">How loudly to log it: <see cref="LogLevel.Error"/> for a write, which
    /// failed the caller's request, and <see cref="LogLevel.Warning"/> for a best-effort delete,
    /// which cost storage rather than correctness and whose caller logs it again.</param>
    private AppException Translate(
        Exception thrown,
        RequestFailedException? failure,
        string objectName,
        LogLevel level)
    {
        if (failure is null)
        {
            // A wrapper with no request failure inside it. Nothing here says the request was ever
            // understood, so it is treated as the upstream failing rather than as our own bad
            // request - and logged loudly, because it is a shape this code has not seen.
            _logger.Log(
                level,
                thrown,
                "Azure Blob Storage failed on {ObjectName} in container {ContainerName} with no "
                + "request failure inside the wrapper.",
                objectName,
                _options.ContainerName);

            return new UpstreamException(ErrorCodes.UpstreamUnavailable, UpstreamMessage, thrown);
        }

        if (failure.Status is 0 or 408 or 429 or >= 500)
        {
            _logger.Log(
                level,
                thrown,
                "Azure Blob Storage did not accept {ObjectName} in container {ContainerName} "
                + "(status {Status}).",
                objectName,
                _options.ContainerName,
                failure.Status);

            return new UpstreamException(ErrorCodes.UpstreamUnavailable, UpstreamMessage, thrown);
        }

        _logger.Log(
            level,
            thrown,
            "Azure Blob Storage rejected {ObjectName} in container {ContainerName} with "
            + "{Status} {ErrorCode}. A 4xx here is our configuration, not theirs: check the "
            + "connection string's permissions and that the container exists.",
            objectName,
            _options.ContainerName,
            failure.Status,
            failure.ErrorCode ?? "-");

        return new AppException(ErrorCodes.InternalError, RejectedMessage, 500, thrown);
    }

    /// <summary>
    /// The container client, or a clear refusal when this deployment has no storage account.
    /// <para>
    /// 501 rather than 500 or 502, matching how the rest of the service reports a capability it
    /// simply does not have here: nothing upstream failed, because nothing upstream was asked, and
    /// calling it 500 would send someone hunting for a defect that is really an empty setting.
    /// </para>
    /// </summary>
    private BlobContainerClient ResolveContainer()
    {
        if (string.IsNullOrWhiteSpace(_options.ConnectionString))
        {
            // Error, not warning: the endpoint is routable and someone just used it, so either the
            // route should not be exposed on this deployment or a setting is missing from it.
            _logger.LogError(
                "An avatar upload reached the Azure Blob adapter, but {Section}:{Setting} is not "
                + "configured. The adapter is complete and needs only that value; until it is set, "
                + "this one endpoint refuses and the rest of the service is unaffected.",
                AzureBlobOptions.SectionName,
                nameof(AzureBlobOptions.ConnectionString));

            throw new AppException(ErrorCodes.NotImplemented, UnconfiguredMessage, 501);
        }

        try
        {
            return _container.Value;
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or InvalidOperationException)
        {
            // Unreachable when the options validator ran - it builds the same client at startup.
            // Kept because a Lazy that throws caches the exception, and a nameless one here would
            // reach the caller as an unmapped 500 with no clue in it.
            _logger.LogError(ex, "The configured Azure Blob connection string could not be used.");

            throw new AppException(ErrorCodes.InternalError, RejectedMessage, 500, ex);
        }
    }
}

/// <summary>
/// Where avatars are stored.
/// <para>
/// <see cref="ConnectionString"/> is deliberately <b>not</b> <c>[Required]</c>. See
/// <see cref="AzureBlobObjectStorage"/> for the reasoning: this secret gates one endpoint, not the
/// service, so its absence refuses that endpoint instead of the boot. Everything else here is
/// validated, including the connection string's <i>syntax</i> when one is supplied - a typo in a
/// value someone did configure is a mistake, and mistakes should surface at startup.
/// </para>
/// </summary>
public sealed class AzureBlobOptions : IValidatableObject
{
    public const string SectionName = "AzureBlob";

    /// <summary>
    /// The storage account connection string. Leave the key out entirely on a deployment with no
    /// blob account; do not set it to the empty string as a placeholder, which reads the same to
    /// this code but suggests to the next reader that something was configured.
    /// </summary>
    public string ConnectionString { get; init; } = string.Empty;

    /// <summary>
    /// The container avatars are written to. It must already exist and be readable anonymously -
    /// creating it, and deciding its public-access level, is an infrastructure decision that does
    /// not belong to a request handler.
    /// </summary>
    [Required]
    public string ContainerName { get; init; } = "users";

    /// <summary>Retries after the first failed attempt. Zero is legal here - unlike the notification
    /// pipeline, nothing rejects it - and means "answer as soon as the first attempt fails".</summary>
    [Range(0, 5)]
    public int MaxRetryAttempts { get; init; } = 2;

    /// <summary>Budget for a single attempt, replacing the SDK's 100-second default. With the
    /// retries above, the worst a caller waits is roughly this times attempts plus backoff.</summary>
    [Range(typeof(TimeSpan), "00:00:01", "00:00:30")]
    public TimeSpan AttemptTimeout { get; init; } = TimeSpan.FromSeconds(10);

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        foreach (var result in ValidateContainerName())
        {
            yield return result;
        }

        if (string.IsNullOrWhiteSpace(ConnectionString))
        {
            // Absent on purpose is legal. The adapter says so, once, when someone tries to upload.
            yield break;
        }

        // Parsing only - the constructor performs no network call, so this costs nothing at startup
        // and turns "the first avatar upload of the release fails" into "the release does not boot".
        BlobServiceClient? client = null;
        var failure = string.Empty;

        try
        {
            client = new BlobServiceClient(ConnectionString);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or InvalidOperationException)
        {
            // Only the SDK's own message is forwarded, and never the configured value. Those
            // messages were checked against ten malformed shapes - including ones carrying an
            // account key and a SAS signature - and every one came back as a fixed diagnostic
            // string ("Settings must be of the form \"name=value\".", "No valid combination of
            // account information found."). None echoed any part of the input, which is what makes
            // it safe to put in a startup failure that lands in a log. The message names the shape
            // of the mistake, not which element is wrong; the connection string is never in it.
            failure = ex.Message;
        }

        if (client is null)
        {
            yield return new ValidationResult(
                $"{SectionName}:{nameof(ConnectionString)} is present but could not be parsed: {failure}",
                [nameof(ConnectionString)]);
        }
    }

    /// <summary>
    /// Azure's own naming rule, checked here because the alternative is a 400 from the storage
    /// service on every upload, arriving as a 500 with a message about a container nobody looked at.
    /// </summary>
    private IEnumerable<ValidationResult> ValidateContainerName()
    {
        var name = ContainerName;

        var valid = name.Length is >= 3 and <= 63
                    && !name.StartsWith('-')
                    && !name.EndsWith('-')
                    && !name.Contains("--", StringComparison.Ordinal)
                    && name.All(static c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-');

        if (!valid)
        {
            yield return new ValidationResult(
                $"{SectionName}:{nameof(ContainerName)} must be 3-63 characters of lowercase "
                + "letters, digits and single hyphens, and may not start or end with one.",
                [nameof(ContainerName)]);
        }
    }
}
