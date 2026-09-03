using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.BackOffice.Accounts;

namespace UserSvc.Api.Controllers.BackOffice;

/// <summary>
/// The back-office account's own credential, changed by the person who owns the mailbox it is
/// mailed to.
/// <para>
/// <b>Anonymous, because it has to be:</b> somebody who cannot sign in cannot present a token, and
/// this is the door for exactly that person. What authorizes the write is the verification ticket -
/// minted by <c>POST /verification/verify</c> against this same address, single-use, and burned in
/// the same transaction as the password write, so a replay of the request finds a spent ticket
/// rather than a second chance. It is not the administrator-driven reset, which lives on the tenant
/// member route, takes a token and a permission code, and is a takeover by another person.
/// </para>
/// <para>
/// <b>It answers 204 and says nothing else, deliberately.</b> There is no body to carry a name, a
/// status or a token: the account it just changed belongs to whoever proved the mailbox, and the
/// only thing this endpoint could add to a bare "done" is a fact about an account that an anonymous
/// caller has no business collecting. Signing in afterwards happens where it always does,
/// <c>POST /back-office/auth/login</c> then <c>/connect/token</c>.
/// </para>
/// <para>
/// <b>The refusals here name what happened, and the send-code half of the same flow does not.</b>
/// A caller who reaches this route holds a ticket for the mailbox, so <c>UNREGISTERED</c> and
/// <c>ACCOUNT_DISABLED</c> tell its owner about their own account - while the same two facts at the
/// send step would tell any stranger which corporate addresses are operator accounts, which is why
/// that step answers every target identically. See <see cref="BackOfficeResetTargetGate"/>.
/// </para>
/// </summary>
[ApiController]
[AllowAnonymous]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/back-office/auth")]
[Produces("application/json")]
public sealed class BackOfficeAccountController(BackOfficeAccountAppService accounts) : ControllerBase
{
    /// <summary>The header a gateway correlates a request across services with. It ends up on the
    /// audit row, which on this path is the only record of where the change came from.</summary>
    private const string RequestIdHeader = "X-Request-Id";

    /// <summary>
    /// Replace the password of the back-office account that owns this mailbox.
    /// </summary>
    /// <remarks>
    /// Every session the account holds dies with the old password: the token version is bumped in
    /// the same transaction, so an access token issued a second earlier stops being accepted.
    /// </remarks>
    /// <response code="204">The password is replaced and every existing session is dead.</response>
    /// <response code="400">The payload is malformed, the ticket is invalid, expired or already
    /// spent, or the address has no back-office account.</response>
    /// <response code="403">The account exists and is disabled. Waiting will not help; an
    /// administrator has to re-enable it.</response>
    /// <response code="429">The per-source budget is spent; see <c>Retry-After</c>.</response>
    [HttpPost("password-reset")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> ResetPassword(
        BackOfficePasswordResetRequest request,
        CancellationToken cancellationToken)
    {
        // Decision 09: failures bubble to AppExceptionHandler, so there is no try/catch and no
        // envelope here.
        await accounts.ResetPasswordAsync(request, RequestContext(), cancellationToken);

        return NoContent();
    }

    /// <summary>
    /// The request facts the reset records but cannot discover for itself. Read here rather than
    /// inside the application service, which sees no HTTP - the same split
    /// <c>HttpContextCurrentUser</c> and the sign-in controller follow.
    /// </summary>
    private BackOfficeResetContext RequestContext() => new(
        HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
        Request.Headers.TryGetValue(RequestIdHeader, out var header) && !string.IsNullOrWhiteSpace(header)
            ? header.ToString()
            : HttpContext.TraceIdentifier);
}
