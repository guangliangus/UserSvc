using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.Sessions;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Auth;

namespace UserSvc.Api.Controllers;

/// <summary>Signed-in device management (decision 11).</summary>
[ApiController]
[Authorize]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/user/sessions")]
[Produces("application/json")]
public sealed class SessionsController(SessionAppService sessions, ICurrentUser currentUser) : ControllerBase
{
    /// <summary>
    /// List the current user's active devices.
    /// <para>
    /// Scoped by <see cref="ICurrentUser.RequireSubject"/> and not by <c>sub</c> alone. A
    /// back-office access token satisfies this action's bare <c>[Authorize]</c> - it is issued by
    /// the same authority - and its <c>sub</c> is an <c>iam.backend_users</c> id, so listing by the
    /// integer alone showed operator 5 the devices of consumer 5 and let the DELETE below sign one
    /// of them out.
    /// </para>
    /// </summary>
    [HttpGet]
    [ProducesResponseType<IReadOnlyList<DeviceSessionResponse>>(StatusCodes.Status200OK)]
    public Task<IReadOnlyList<DeviceSessionResponse>> List(CancellationToken cancellationToken) =>
        sessions.ListDevicesAsync(
            currentUser.RequireSubject(), currentUser.SessionId ?? string.Empty, cancellationToken);

    /// <summary>Sign one device out. Revoking an already-revoked session succeeds idempotently.</summary>
    [HttpDelete("{sessionId}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Revoke(string sessionId, CancellationToken cancellationToken)
    {
        var reason = sessionId == currentUser.SessionId
            ? RevocationReasons.Self
            : RevocationReasons.OtherDevice;

        await sessions.RevokeDeviceAsync(currentUser.RequireSubject(), sessionId, reason, cancellationToken);
        return NoContent();   // Decision 09: a delete answers 204 with no body.
    }
}
