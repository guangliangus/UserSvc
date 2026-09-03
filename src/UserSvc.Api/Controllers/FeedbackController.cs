using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Api.Middleware;
using UserSvc.Application.Features.Feedback;
using UserSvc.Application.Ports.Feedback;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Api.Controllers;

/// <summary>
/// The personal-centre feedback form: what categories exist, and taking one submission.
/// <para>
/// Both routes require a signed-in consumer. The list endpoint does not need to know who is asking
/// and deliberately never reads the caller's id - it is behind authentication because the form it
/// feeds is, not because the catalogue is a secret.
/// </para>
/// <para>
/// <b>There is no rate limit on either route, and that is a known gap rather than a decision.</b>
/// The service being replaced had none, adding one changes the contract for clients written against
/// it, and a submission already costs an authenticated account. It is the first thing to add if
/// this is ever abused.
/// </para>
/// </summary>
[ApiController]
[Authorize]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/feedback")]
[Produces("application/json")]
public sealed class FeedbackController(FeedbackAppService feedback, ICurrentUser currentUser) : ControllerBase
{
    /// <summary>
    /// The feedback categories, in the order the drop-down should render them.
    /// <para>
    /// The language comes from the request context, which is the same negotiation every error
    /// message in the service goes through: <c>X-Language</c> first, then <c>Accept-Language</c>,
    /// then English. This route used to read <c>X-Language</c> off the request itself, and the
    /// difference was visible - a browser that sent only <c>Accept-Language: ja</c> was refused in
    /// Japanese and offered an English drop-down on the very next call.
    /// </para>
    /// </summary>
    /// <response code="200">The active categories, in the negotiated language. Possibly empty.</response>
    /// <response code="401">No valid token.</response>
    [HttpGet("types")]
    [ProducesResponseType<IReadOnlyList<FeedbackTypeResponse>>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public Task<IReadOnlyList<FeedbackTypeResponse>> ListTypes(CancellationToken cancellationToken) =>
        feedback.ListTypesAsync(RequestContextAccessor.LocaleOf(HttpContext), cancellationToken);

    /// <summary>
    /// Submit feedback, with up to five images attached on the repeated <c>images</c> field.
    /// </summary>
    /// <response code="200">Stored. The body carries the new submission's id and triage status.</response>
    /// <response code="400">A field is missing or too long, the category is unknown or retired, or an
    /// attached image is too large, too numerous, or not an image.</response>
    /// <response code="401">No valid token.</response>
    /// <response code="500">The image could not be stored, or the row could not be written.</response>
    [HttpPost]
    [Consumes("multipart/form-data")]
    [RequestSizeLimit(FeedbackLimits.MaxRequestBytes)]
    [RequestFormLimits(MultipartBodyLengthLimit = FeedbackLimits.MaxRequestBytes)]
    [ProducesResponseType<SubmitFeedbackResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public Task<SubmitFeedbackResponse> Submit(
        [FromForm] SubmitFeedbackRequest request,
        CancellationToken cancellationToken) =>
        // 200 rather than 201: there is no endpoint that reads a submission back, so there is no
        // Location to point a 201 at, and the clients were written against 200.
        feedback.SubmitAsync(currentUser.RequireConsumerId(), request, ReadImages(), cancellationToken);

    /// <summary>
    /// The attached images, adapted onto the port the application layer speaks.
    /// <para>
    /// Read straight off the form rather than bound as a parameter so that the field name is the
    /// one literal the contract names, and so that a request with no images is an empty list rather
    /// than a null the service has to defend against.
    /// </para>
    /// </summary>
    private IReadOnlyList<IUploadedFile> ReadImages() =>
        [.. Request.Form.Files
            .GetFiles(FeedbackLimits.ImagesFieldName)
            .Select(file => new FormFileUploadedFile(file))];
}

/// <summary>
/// Adapts one <see cref="IFormFile"/> onto <see cref="IUploadedFile"/>.
/// <para>
/// <see cref="IFormFile.OpenReadStream"/> hands back a fresh stream on every call, which is exactly
/// what the port requires: the same file is opened twice, once to sniff its leading bytes and once
/// to upload it.
/// </para>
/// </summary>
internal sealed class FormFileUploadedFile(IFormFile file) : IUploadedFile
{
    public long Size => file.Length;

    public Stream Open() => file.OpenReadStream();
}
