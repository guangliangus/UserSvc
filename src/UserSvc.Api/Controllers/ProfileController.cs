using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.Profile;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Api.Controllers;

/// <summary>
/// Decision 07: controllers rather than Minimal API — this service leans hard on cross-cutting
/// concerns (rate limiting, idempotency keys, permission attributes, versioning, automatic
/// validation) where the filter and attribute ecosystem is mature.
/// Decision 08: URL-segment versioning, so the gateway can route by path and version distribution
/// is visible at a glance in the logs.
/// </summary>
[ApiController]
[Authorize]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/user/profile")]
[Produces("application/json")]
public sealed class ProfileController(ProfileAppService profiles, ICurrentUser currentUser) : ControllerBase
{
    /// <summary>Read the current user's profile.</summary>
    [HttpGet]
    [ProducesResponseType<ProfileResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public Task<ProfileResponse> Get(CancellationToken cancellationToken) =>
        // Decision 09: success returns the DTO itself, with no { success, data } envelope, and
        // failures bubble up to AppExceptionHandler. Controllers carry no try/catch.
        profiles.GetAsync(currentUser.RequireUserId(), cancellationToken);

    /// <summary>Update the current user's profile. Omitted fields are left unchanged.</summary>
    [HttpPatch]
    [ProducesResponseType<ProfileResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public Task<ProfileResponse> Update(UpdateProfileRequest request, CancellationToken cancellationToken) =>
        profiles.UpdateAsync(currentUser.RequireUserId(), request, cancellationToken);
}
