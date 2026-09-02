using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using UserSvc.Application.Features.RiskControl;

namespace UserSvc.Api.Controllers;

/// <summary>
/// The way out of a <c>CAPTCHA_REQUIRED</c> refusal. The client runs the provider's SDK, posts the
/// resulting token here, and replays its send-code request with the one-time token this returns.
/// <para>
/// <b>Public, and necessarily so</b> - the caller has been refused a verification code, so by
/// definition they have no session yet. That makes this one of the most exposed endpoints in the
/// service, and the reason everything it can spend is bounded: the provider call is behind a
/// resilience pipeline with a total timeout, the failed assessments are counted, and the credential
/// it issues lives for two minutes and is bound to one target and one device.
/// </para>
/// <para>
/// It answers nothing about the target it was given - no lookup happens on this path - so it cannot
/// be used to learn whether an address is registered. That property is worth keeping: it is the
/// same question the send endpoint is criticised for answering.
/// </para>
/// </summary>
[ApiController]
[AllowAnonymous]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/verification/captcha")]
[Produces("application/json")]
public sealed class CaptchaController(CaptchaAppService captcha) : ControllerBase
{
    /// <summary>Client-reported and forgeable. It binds the token and feeds counting, nothing else.</summary>
    private const string DeviceIdHeader = "X-Device-ID";

    /// <summary>Selects the platform's provider key: <c>ios</c>, <c>android</c> or <c>web</c>.</summary>
    private const string PlatformHeader = "X-Platform";

    /// <summary>Only consulted when the deployment configured no region of its own.</summary>
    private const string LanguageHeader = "X-Language";

    /// <summary>
    /// Verify a CAPTCHA and get a one-time token that bypasses the send-code throttle.
    /// </summary>
    /// <response code="200">The challenge was passed; the token is in the body.</response>
    /// <response code="400">The payload is malformed, or the challenge was not passed. Retrying with a fresh provider token is allowed and unlimited.</response>
    /// <response code="429">Too many failed attempts, or this subject is already cooling down; see <c>Retry-After</c>. Another CAPTCHA will not help.</response>
    /// <response code="500">No CAPTCHA provider is configured on this deployment, or the provider refused our own credentials.</response>
    /// <response code="502">The CAPTCHA provider could not be reached, or the issued token could not be stored.</response>
    [HttpPost("verify")]
    [ProducesResponseType<CaptchaVerifyResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(StatusCodes.Status502BadGateway)]
    public Task<CaptchaVerifyResponse> Verify(CaptchaVerifyRequest request, CancellationToken cancellationToken) =>
        // Decision 09: the DTO is the response, there is no envelope, and every failure bubbles to
        // AppExceptionHandler. No try/catch here.
        captcha.VerifyAsync(request, ReadContext(), cancellationToken);

    /// <summary>
    /// The five per-request facts the CAPTCHA path needs from outside the payload.
    /// <para>
    /// Every header is read leniently, exactly as <c>VerificationController</c> reads the device id
    /// and for the same reason: the Go service rejected a request missing any of its four device
    /// headers, that middleware has not been ported, and converging on it is a decision for the
    /// whole API surface rather than for one controller. Absent headers degrade to safe values -
    /// no device binds the token to "no device", no platform uses the default provider key, no
    /// language falls back to the deployment's own region.
    /// </para>
    /// </summary>
    private CaptchaRequestContext ReadContext() => new(
        Request.Headers[DeviceIdHeader].ToString(),
        Request.Headers[PlatformHeader].ToString(),
        Request.Headers[LanguageHeader].ToString(),
        HttpContext.Connection.RemoteIpAddress?.ToString(),
        Request.Headers[HeaderNames.UserAgent].ToString());
}
