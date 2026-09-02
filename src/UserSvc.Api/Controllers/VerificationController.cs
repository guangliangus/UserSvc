using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.Verification;

namespace UserSvc.Api.Controllers;

/// <summary>
/// Proving control of a phone number or a mailbox. <b>Both routes are public</b> - they have to be,
/// since registration and password reset both start here, before anyone has a token.
/// <para>
/// That makes these two endpoints the most exposed surface in the service, and the abuse controls
/// that would elsewhere be a filter live in the application service instead: they must run in a
/// specific order relative to payload validation, and they must be exercised by unit tests rather
/// than only by whatever the pipeline happens to be wired to that day.
/// </para>
/// </summary>
[ApiController]
[AllowAnonymous]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/verification")]
[Produces("application/json")]
public sealed class VerificationController(VerificationAppService verification) : ControllerBase
{
    /// <summary>Client-reported and forgeable. It feeds risk-control counting only.</summary>
    private const string DeviceIdHeader = "X-Device-ID";

    /// <summary>
    /// Send a verification code to a phone number or email address.
    /// </summary>
    /// <response code="200">The send was accepted. It says nothing about whether the target exists.</response>
    /// <response code="400">The payload is malformed, the target is not registered, or the captcha token was refused.</response>
    /// <response code="403">A verification challenge has to be completed before this will be accepted.</response>
    /// <response code="409">The target is already linked to an account (bind only).</response>
    /// <response code="429">The per-IP budget or the per-target cooldown is spent; see <c>Retry-After</c>.</response>
    /// <response code="502">The notification service could not be reached.</response>
    [HttpPost("send")]
    [ProducesResponseType<SendVerificationCodeResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status502BadGateway)]
    public Task<SendVerificationCodeResponse> Send(
        SendVerificationCodeRequest request,
        CancellationToken cancellationToken) =>
        // Decision 09: the DTO is the response, there is no envelope, and every failure bubbles to
        // AppExceptionHandler. No try/catch here.
        verification.SendVerificationCodeAsync(request, ReadContext(), cancellationToken);

    /// <summary>
    /// Exchange a code for a verification ticket. The ticket is returned once, in plaintext, and is
    /// what the following registration, reset or bind call presents.
    /// </summary>
    /// <response code="200">The code was correct; the ticket is in the body.</response>
    /// <response code="400">The code is wrong, expired, or already used.</response>
    [HttpPost("verify")]
    [ProducesResponseType<VerifyCodeResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public Task<VerifyCodeResponse> Verify(VerifyCodeRequest request, CancellationToken cancellationToken) =>
        verification.VerifyCodeAsync(request, cancellationToken);

    /// <summary>
    /// The two per-request facts the send path needs from outside the payload.
    /// <para>
    /// The device id header is read leniently - absent means an empty hash, not a refusal. The Go
    /// service rejected a request missing any of its four device headers, and that middleware has
    /// not been ported; converging on it is a decision for the whole API surface, not for this one
    /// controller to make unilaterally.
    /// </para>
    /// </summary>
    private VerificationRequestContext ReadContext() => new(
        HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
        HttpContext.Request.Headers[DeviceIdHeader].ToString());
}
