using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Localization;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Feedback;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Feedback;

namespace UserSvc.Application.Features.Feedback;

/// <summary>
/// Reading the category list and taking one submission. Two use cases, and the second one is the
/// interesting one.
/// <para>
/// <b>Everything that can refuse the submission runs before anything is uploaded.</b> The text, the
/// image count, each image's size, each image's real type, and finally whether the category exists
/// - all of it happens while the only thing spent is CPU. A rejected submission therefore leaves
/// nothing behind: no object in storage, no row, nothing for a sweep job to find later.
/// </para>
/// <para>
/// <b>The object store and the database are not one transaction, and cannot be made into one.</b>
/// Uploads happen first because a row pointing at an object that does not exist is worse than an
/// object nothing points at. Every failure after the first successful upload deletes what this
/// request put there - best effort, because a failed cleanup must not replace the real error with a
/// cleanup error. What survives that is the narrow window where the process dies between the last
/// upload and the commit: it leaves orphaned objects, nothing more, and no user-visible
/// consequence. There is deliberately no sweep job for them yet.
/// </para>
/// </summary>
public sealed class FeedbackAppService(
    IFeedbackRepository feedback,
    IObjectStorage storage,
    IUnitOfWork unitOfWork,
    IClock clock,
    ILogger<FeedbackAppService> logger)
{
    /// <summary>Where a feedback image lands: one folder per account, one opaque name per image.
    /// The name is random rather than derived from the upload's filename, which is caller-controlled
    /// text and has no business becoming a path.</summary>
    private const string ObjectNamePrefix = "feedback";

    /// <summary>
    /// An object name is unique per upload, so the bytes behind one URL never change and may be
    /// cached for as long as a browser is willing to.
    /// </summary>
    private const string ImageCacheControl = "public, max-age=31536000";

    /// <summary>
    /// <c>inline</c>, so a support agent opening the URL sees the photo instead of downloading it.
    /// <para>
    /// <b>That is only safe because of the sniff.</b> Serving caller-supplied bytes inline from a
    /// domain the browser trusts is the classic stored-XSS route, and what stands between this
    /// header and that is <see cref="FeedbackImageRules"/> having already read the file's leading
    /// bytes and confirmed they are one of five raster formats. If that check is ever loosened,
    /// this value has to become <c>attachment</c> in the same commit.
    /// </para>
    /// </summary>
    private const string ImageContentDisposition = "inline";

    /// <summary>What the caller was doing, for the refusal a deployment with no object store
    /// answers. Submitting a report with no photo attached never reaches the store and is
    /// unaffected, which is why this names the images rather than feedback as a whole.</summary>
    private const string ImagesUnavailableMessage =
        "Attaching images to feedback is not available on this deployment.";

    /// <summary>
    /// What lands in <c>created_by</c> / <c>updated_by</c>. The person is already identified by
    /// <c>user_id</c>, so the audit columns record the only other thing worth recording: that no
    /// operator typed this row, the service did. Written rather than left NULL because a NULL in an
    /// audit column reads as "nobody has looked at this yet", which is a different fact.
    /// </summary>
    private const string SystemActor = "system";

    /// <summary>
    /// The active categories, localized for the caller's language.
    /// <para>
    /// <paramref name="language"/> is normalized through <see cref="SupportedLocales"/> - the same
    /// table the error-message bundles are keyed by, so a client cannot be answered in one language
    /// by this endpoint and another by the next. It accepts a raw header value as readily as an
    /// already-negotiated locale, because normalization is idempotent and this service should not
    /// depend on which of the two its caller happens to hold. Nothing here is per-user: the list is
    /// the same for everyone in a given language, and the endpoint deliberately never learns who is
    /// asking.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<FeedbackTypeResponse>> ListTypesAsync(
        string? language,
        CancellationToken cancellationToken)
    {
        var locale = SupportedLocales.Normalize(language);
        var types = await feedback.ListActiveTypesAsync(cancellationToken);

        // The repository's order is the drop-down's order and is preserved exactly. An empty
        // catalogue is an empty array, never null - the client maps over this without a guard.
        var response = new List<FeedbackTypeResponse>(types.Count);

        foreach (var type in types)
        {
            var label = type.ResolveLabel(locale);

            if (label.Length == 0)
            {
                // The row still ships - a category the endpoint accepts must appear in the list it
                // publishes, or the form is shorter than the contract. But an empty label only
                // happens when the jsonb is absent, malformed, or has no English fallback, and all
                // three are operator mistakes that are otherwise completely silent: the drop-down
                // renders a blank line and nothing anywhere says why.
                logger.LogWarning(
                    "Feedback category {TypeCode} has no label for {Locale} and no English fallback; "
                    + "its labels column is empty or not an object of strings.",
                    type.Code,
                    locale);
            }

            response.Add(new FeedbackTypeResponse { Code = type.Code, Label = label });
        }

        return response;
    }

    /// <summary>Validate, upload, persist - in that order, and with the whole of the first step
    /// finished before the second begins. See the class remarks for why.</summary>
    public async Task<SubmitFeedbackResponse> SubmitAsync(
        int userId,
        SubmitFeedbackRequest request,
        IReadOnlyList<IUploadedFile>? files,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var content = request.Content.Trim();
        var typeCode = request.Type.Trim();
        RequireUsableContent(content);

        // Before the category lookup on purpose: a request carrying six images is malformed
        // whatever category it names, and refusing it here costs no query. The unit tests assert
        // that no repository call happens on this path, because that ordering is easy to lose in a
        // later edit and impossible to notice.
        var pending = FeedbackImageRules.Validate(files);

        if (await feedback.FindActiveTypeAsync(typeCode, cancellationToken) is null)
        {
            // 400, not 404. The category is a field of the request, not the resource being
            // addressed, and the caller's remedy is to pick a different value from the list
            // endpoint - which is what 400 tells them and 404 does not.
            throw new BadRequestException(
                ErrorCodes.BadRequest, "That feedback type is not one this service accepts.");
        }

        var uploaded = await UploadAllAsync(pending, userId, cancellationToken);

        var submission = new FeedbackSubmission
        {
            UserId = userId,
            TypeCode = typeCode,
            Content = content,

            // Stored exactly as typed, and deliberately not overwritten from the profile: these are
            // the contact details for this submission, and a person filing feedback about a
            // mistyped address in their profile must be able to give a different one.
            Name = request.Name.Trim(),
            Email = request.Email.Trim(),

            ImageUrls = JsonSerializer.Serialize(uploaded.Select(image => image.Url)),
            Status = FeedbackStatuses.Pending,
            CreatedAt = clock.UtcNow,
            UpdatedAt = clock.UtcNow,
            CreatedBy = SystemActor,
            UpdatedBy = SystemActor,
        };

        try
        {
            feedback.Add(submission);
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (Exception)
        {
            // The row did not land, so nothing will ever point at these objects. Delete them before
            // the error leaves, then let the original exception through untouched.
            await DeleteQuietlyAsync(uploaded.Select(image => image.ObjectName), cancellationToken);
            throw;
        }

        return new SubmitFeedbackResponse { Id = submission.Id, Status = submission.Status };
    }

    /// <summary>
    /// Content that is only whitespace is not content, and the limit is counted in code points.
    /// <para>
    /// The request validator checks both of these too. Repeating them is not belt and braces: this
    /// method's own failure semantics must not depend on a filter it does not own, or a direct
    /// caller - a future back-office importer, a test - would store an empty submission.
    /// </para>
    /// </summary>
    private static void RequireUsableContent(string content)
    {
        if (content.Length == 0)
        {
            throw new BadRequestException(ErrorCodes.ValidationFailed, "Feedback content is required.");
        }

        if (FeedbackLimits.RuneCount(content) > FeedbackLimits.MaxContentRunes)
        {
            throw new BadRequestException(
                ErrorCodes.ValidationFailed,
                $"Feedback content must be at most {FeedbackLimits.MaxContentRunes} characters.");
        }
    }

    /// <summary>
    /// Uploads the images one at a time, in the order they were attached, and unwinds on the first
    /// failure.
    /// <para>
    /// Serial rather than parallel: five 5 MiB uploads at once from every submitting client is a
    /// self-inflicted load spike on the storage account, and nobody is waiting on the difference.
    /// The order is preserved because it is the order the URLs are stored in, and a triage screen
    /// showing "photo 3" has to mean the third photo the person attached.
    /// </para>
    /// </summary>
    private async Task<IReadOnlyList<StoredImage>> UploadAllAsync(
        IReadOnlyList<PendingImage> pending,
        int userId,
        CancellationToken cancellationToken)
    {
        if (pending.Count == 0)
        {
            return [];
        }

        var uploaded = new List<StoredImage>(pending.Count);

        foreach (var image in pending)
        {
            // The name is composed here rather than read back from the store, because it is what
            // addresses the object for a later delete and the port only returns a URL.
            var objectName = NextObjectName(userId, image.ContentType);

            try
            {
                // The port does not dispose what it is given - the caller owns the stream - so this
                // using block is the only thing that closes it.
                await using var content = image.File.Open();

                var url = await StoreAsync(objectName, content, image.ContentType, cancellationToken);

                uploaded.Add(new StoredImage(objectName, url.ToString()));
            }
            catch (Exception)
            {
                // Only what this request already put there. The upload that just failed is not in
                // the list on purpose: a failed PUT may or may not have written bytes, and this
                // service has no way to tell - but a delete of a name that does not exist is
                // harmless, while a delete of a name a *retry* has since written is not.
                await DeleteQuietlyAsync(uploaded.Select(item => item.ObjectName), cancellationToken);
                throw;
            }
        }

        return uploaded;
    }

    /// <summary>
    /// One image into the store, with this feature's name on the one refusal that has to carry it.
    /// <para>
    /// The store is shared with avatar uploads and cannot tell which of the two is calling, so its
    /// own 501 names the store and not a feature - see <see cref="IObjectStorage.PutAsync"/>.
    /// Teaching the adapter the difference would make one use case's wording an adapter's business
    /// and point the dependency back up the way the port exists to prevent, so the sentence is
    /// composed here instead, where "this is a photo attached to a feedback report" is already
    /// known. The status and the error code are carried over unchanged: it is the same condition,
    /// said to the person who was actually attaching a photo.
    /// </para>
    /// </summary>
    private async Task<Uri> StoreAsync(
        string objectName,
        Stream content,
        string contentType,
        CancellationToken cancellationToken)
    {
        try
        {
            return await storage.PutAsync(
                objectName,
                content,
                new ObjectHttpHeaders(contentType, ImageCacheControl, ImageContentDisposition),
                cancellationToken);
        }
        catch (AppException ex) when (ex.ErrorCode == ErrorCodes.NotImplemented)
        {
            throw new AppException(ErrorCodes.NotImplemented, ImagesUnavailableMessage, ex.StatusCode, ex);
        }
    }

    /// <summary>
    /// Deletes objects on a failure path and never throws.
    /// <para>
    /// A cleanup that raised would replace the real reason the submission failed - the storage
    /// outage, the constraint violation - with a message about a delete, and the caller would be
    /// told the wrong thing about what went wrong. A leaked object costs storage; a lost error
    /// costs an afternoon.
    /// </para>
    /// <para>
    /// It is given the request's own cancellation token rather than a fresh one, so a cleanup after
    /// the client disconnects fails immediately and is logged. Reaching for
    /// <see cref="CancellationToken.None"/> here to "make cleanup reliable" would let a cancelled
    /// request keep issuing deletes against a store that may be the reason it was cancelled.
    /// </para>
    /// </summary>
    private async Task DeleteQuietlyAsync(IEnumerable<string> objectNames, CancellationToken cancellationToken)
    {
        foreach (var objectName in objectNames)
        {
            try
            {
                await storage.DeleteAsync(objectName, cancellationToken);
            }
            catch (Exception ex)
            {
                logger.LogWarning(
                    ex,
                    "A feedback image could not be cleaned up after a failed submission and is now orphaned: {ObjectName}",
                    objectName);
            }
        }
    }

    /// <summary>A fresh, unguessable name under the submitting account's folder. Version 7 so names
    /// sort by creation time in a storage listing, which is how anyone browsing the container
    /// actually looks for something.</summary>
    private static string NextObjectName(int userId, string contentType) => string.Create(
        CultureInfo.InvariantCulture,
        $"{ObjectNamePrefix}/{userId}/{Guid.CreateVersion7():n}{FeedbackImageRules.ExtensionFor(contentType)}");

    /// <summary>
    /// One stored image, both ways round: the URL goes into the row, the object name is what a
    /// cleanup deletes. The port hands back only the first, so the second is kept here.
    /// </summary>
    private sealed record StoredImage(string ObjectName, string Url);
}
