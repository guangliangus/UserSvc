using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.Account;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Api.Controllers;

/// <summary>
/// The account itself, as opposed to the profile hanging off it. One route today: closing it.
/// </summary>
[ApiController]
[Authorize]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/account")]
[Produces("application/json")]
public sealed class AccountController(AccountAppService accounts, ICurrentUser currentUser) : ControllerBase
{
    /// <summary>
    /// Close the caller's own account. Every device is signed out immediately and every login
    /// identity is released; nothing is physically deleted.
    /// <para>
    /// <b>It acts on the id in the token and takes no parameter</b>, so there is no request an
    /// attacker can shape to close somebody else's account, and no id in a URL for a proxy log to
    /// keep. It is also why the 404 below leaks nothing: the only account it can describe is the
    /// caller's own.
    /// </para>
    /// <para>
    /// Repeating the call is safe and answers the same way.
    /// </para>
    /// </summary>
    /// <response code="204">The account is closed. Every token the caller holds is already dead.</response>
    /// <response code="401">No valid token.</response>
    /// <response code="404">The token names an account that does not exist.</response>
    /// <response code="502">The sessions could not be revoked, so the account was left open. Retry.</response>
    [HttpDelete]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status502BadGateway)]
    public async Task<IActionResult> Deregister(CancellationToken cancellationToken)
    {
        await accounts.DeregisterAsync(currentUser.RequireUserId(), cancellationToken);
        return NoContent();   // Decision 09: a delete answers 204 with no body.
    }
}
