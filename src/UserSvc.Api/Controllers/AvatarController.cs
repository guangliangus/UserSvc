using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Profile;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Api.Controllers;

/// <summary>
/// Uploading the picture on the signed-in user's profile.
/// <para>
/// A separate controller from <see cref="ProfileController"/> rather than a third action on it: the
/// profile endpoints speak JSON and this one speaks <c>multipart/form-data</c>, which means a
/// different <c>Consumes</c>, a different set of statuses and a body limit that has nothing to do
/// with the others. Routing keeps them next to each other under <c>/api/v1/user</c> regardless.
/// </para>
/// <para>
/// The controller does almost nothing on purpose. It has exactly one job the application layer
/// cannot do - turning an <c>IFormFile</c> into a stream and a couple of claims - and every
/// judgement about whether those bytes are an acceptable avatar belongs to
/// <see cref="AvatarAppService"/>, where it is unit-testable without an HTTP request. In particular
/// the size check is <b>not</b> duplicated here: a check against
/// <see cref="Microsoft.AspNetCore.Http.IFormFile.Length"/> would only be re-reading the same claim
/// the service already refuses to trust.
/// </para>
/// </summary>
[ApiController]
[Authorize]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/user/avatar")]
[Produces("application/json")]
public sealed class AvatarController(AvatarAppService avatars, ICurrentUser currentUser) : ControllerBase
{
    /// <summary>
    /// Replace the current user's avatar. The image is sent as the <c>avatar</c> part of a
    /// <c>multipart/form-data</c> body and must be a JPEG or PNG of at most 200 KB - decided by
    /// reading the file's leading bytes, not by what the part claims to be.
    /// </summary>
    /// <response code="200">The profile as it now reads, with <c>avatar</c> pointing at the new image.</response>
    /// <response code="413">The image is larger than 200 KB.</response>
    /// <response code="415">The file is not a JPEG or a PNG.</response>
    /// <response code="501">This deployment has no object storage configured.</response>
    /// <response code="502">Object storage is unreachable, throttling, or answered a 5xx.</response>
    [HttpPost]
    [Consumes("multipart/form-data")]
    [ProducesResponseType<ProfileResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status413PayloadTooLarge)]
    [ProducesResponseType(StatusCodes.Status415UnsupportedMediaType)]
    [ProducesResponseType(StatusCodes.Status501NotImplemented)]
    [ProducesResponseType(StatusCodes.Status502BadGateway)]
    public async Task<ProfileResponse> Upload(IFormFile? avatar, CancellationToken cancellationToken)
    {
        // Declared nullable so model binding does not produce its own "the avatar field is
        // required" ModelState 400, whose body would carry a different error code than every other
        // refusal on this endpoint. Missing and empty are the same mistake to the caller, so they
        // get the same answer.
        if (avatar is null || avatar.Length == 0)
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest,
                "An image must be sent as the 'avatar' part of a multipart/form-data body.");
        }

        // OpenReadStream is forward-only and tied to the request body, which is why the service
        // buffers rather than rewinding. Disposed here, on every path, including the throwing ones.
        await using var content = avatar.OpenReadStream();

        return await avatars.UploadAsync(
            currentUser.RequireUserId(),
            new AvatarUpload(content, avatar.ContentType, avatar.Length),
            cancellationToken);
    }
}
