using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.Passkeys;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Api.Controllers;

/// <summary>
/// Passkeys: enrolling a WebAuthn credential, signing in with one, and managing the ones an account
/// holds.
/// <para>
/// <b>Two of these seven routes are anonymous and the other five are not</b>, which is why the
/// class carries <c>[Authorize]</c> and the login pair opts out. Registration adds a credential to
/// the account making the request, so it needs a token; login is how a token is obtained in the
/// first place, so it cannot need one. The class-level default is the safe direction: a new route
/// added here is authenticated unless somebody deliberately says otherwise.
/// </para>
/// <para>
/// <b>Login finish issues no tokens</b>, exactly as registration issues none: OpenIddict owns token
/// minting (decision 10) and <c>/connect/token</c> is the only place it happens. This endpoint's
/// answer is the authenticated user id; the client exchanges it there.
/// </para>
/// </summary>
[ApiController]
[Authorize]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/auth/passkey")]
[Produces("application/json")]
public sealed class PasskeyController(PasskeyAppService passkeys, ICurrentUser currentUser) : ControllerBase
{
    /// <summary>
    /// Start enrolling a passkey. The response body is handed to <c>navigator.credentials.create</c>
    /// unchanged.
    /// </summary>
    /// <response code="200">The challenge and the flow handle to return with it.</response>
    /// <response code="401">No valid token.</response>
    /// <response code="403">The account is not active.</response>
    /// <response code="502">The ceremony store is unreachable, so no challenge could be issued.</response>
    [HttpPost("register/begin")]
    [ProducesResponseType<PasskeyChallengeResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status502BadGateway)]
    public Task<PasskeyChallengeResponse> BeginRegistration(
        PasskeyRegisterBeginRequest? request,
        CancellationToken cancellationToken) =>
        // The body is optional: a client with no label to suggest has nothing to send, and the Go
        // clients send none. Binding null must therefore not be a 400.
        passkeys.BeginRegistrationAsync(
            currentUser.RequireConsumerId(),
            request ?? new PasskeyRegisterBeginRequest(),
            cancellationToken);

    /// <summary>Finish enrolling a passkey by returning the authenticator's attestation.</summary>
    /// <response code="200">The credential is stored.</response>
    /// <response code="400">The flow expired or was already spent, the credential is malformed, or it did not verify.</response>
    /// <response code="401">No valid token.</response>
    /// <response code="409">That credential is already registered.</response>
    [HttpPost("register/finish")]
    [ProducesResponseType<PasskeyRegistrationResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public Task<PasskeyRegistrationResponse> FinishRegistration(
        PasskeyRegisterFinishRequest request,
        CancellationToken cancellationToken) =>
        passkeys.FinishRegistrationAsync(currentUser.RequireConsumerId(), request, cancellationToken);

    /// <summary>
    /// Start a passkey sign-in.
    /// <para>
    /// An identifier may be supplied to narrow the credential list, but the response is deliberately
    /// identical whether or not it matches an account - this endpoint is anonymous and must not
    /// answer "is this address registered".
    /// </para>
    /// </summary>
    /// <response code="200">The challenge and the flow handle to return with it.</response>
    /// <response code="429">The per-IP budget is spent; see <c>Retry-After</c>.</response>
    /// <response code="502">The ceremony store is unreachable, so no challenge could be issued.</response>
    [HttpPost("login/begin")]
    [AllowAnonymous]
    [ProducesResponseType<PasskeyChallengeResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status502BadGateway)]
    public Task<PasskeyChallengeResponse> BeginLogin(
        PasskeyLoginBeginRequest? request,
        CancellationToken cancellationToken) =>
        passkeys.BeginLoginAsync(
            request ?? new PasskeyLoginBeginRequest(),
            new PasskeyRequestContext(HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty),
            cancellationToken);

    /// <summary>
    /// Finish a passkey sign-in by returning the authenticator's assertion.
    /// </summary>
    /// <response code="200">The assertion verified. The body names the account that just authenticated.</response>
    /// <response code="400">The flow expired or was already spent, or the assertion is malformed.</response>
    /// <response code="401">
    /// The credential is unknown, the assertion did not verify, or - with error code
    /// <c>PASSKEY_POSSIBLE_CLONE</c> - the authenticator's signature counter went backwards, which
    /// means the credential has been copied off the device that created it.
    /// </response>
    /// <response code="403">The account is not active.</response>
    [HttpPost("login/finish")]
    [AllowAnonymous]
    [ProducesResponseType<PasskeyLoginResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public Task<PasskeyLoginResponse> FinishLogin(
        PasskeyLoginFinishRequest request,
        CancellationToken cancellationToken) =>
        passkeys.FinishLoginAsync(request, cancellationToken);

    /// <summary>The passkeys on the current account. An account with none gets an empty list.</summary>
    [HttpGet]
    [ProducesResponseType<PasskeyListResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public Task<PasskeyListResponse> List(CancellationToken cancellationToken) =>
        passkeys.ListAsync(currentUser.RequireConsumerId(), cancellationToken);

    /// <summary>Relabel one passkey.</summary>
    /// <response code="404">No such passkey on this account. Somebody else's id answers the same way.</response>
    [HttpPatch("{id:int}")]
    [ProducesResponseType<PasskeyResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public Task<PasskeyResponse> Rename(
        int id,
        RenamePasskeyRequest request,
        CancellationToken cancellationToken) =>
        passkeys.RenameAsync(currentUser.RequireConsumerId(), id, request, cancellationToken);

    /// <summary>
    /// Remove one passkey.
    /// </summary>
    /// <response code="204">Removed.</response>
    /// <response code="404">No such passkey on this account. Somebody else's id answers the same way.</response>
    /// <response code="409">
    /// It is the account's only remaining way to sign in. Add a password or bind an address first -
    /// removing it would lock the account permanently.
    /// </response>
    [HttpDelete("{id:int}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Delete(int id, CancellationToken cancellationToken)
    {
        await passkeys.DeleteAsync(currentUser.RequireConsumerId(), id, cancellationToken);

        return NoContent();
    }
}
