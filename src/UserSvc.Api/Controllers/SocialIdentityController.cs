using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Api.Controllers;

/// <summary>
/// Signing in and linking accounts with WeChat, the WeChat mini program, Firebase (Google / Apple /
/// Facebook) and LINE.
/// <para>
/// <b>None of these endpoints returns a token, and that is decision 10 rather than an oversight.</b>
/// A sign-in here resolves <i>which account</i> a third-party credential belongs to - creating it
/// if this is the first time - and the client then signs in at <c>/connect/token</c>, exactly as it
/// does after registering. OpenIddict is the only thing in this service that mints credentials;
/// a second path would eventually disagree with it about what a session is.
/// </para>
/// <para>
/// The consequence for a client is one extra round trip, and the consequence for this service is
/// that the account-status gate, the device cap and the session row all keep living in one place.
/// </para>
/// <para>
/// The routes split by authentication and it is worth reading the split: <c>state</c> and
/// <c>login</c> are anonymous because nobody has a token yet, while <c>bind</c> and <c>unbind</c>
/// require one - they act on the caller's own account, and the session <i>is</i> the consent.
/// </para>
/// </summary>
[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/auth")]
[Produces("application/json")]
public sealed class SocialIdentityController(
    SocialIdentityAppService social,
    ICurrentUser currentUser) : ControllerBase
{
    /// <summary>Client-reported and forgeable; it is echoed inside the signed state and never trusted.</summary>
    private const string DeviceIdHeader = "X-Device-ID";

    // ------------------------------------------------------------------ WeChat

    /// <summary>Start a WeChat web OAuth flow.</summary>
    /// <response code="200">The AppID, scope and a five-minute signed state.</response>
    [HttpGet("wechat/state")]
    [AllowAnonymous]
    [ProducesResponseType<WechatOAuthStartResponse>(StatusCodes.Status200OK)]
    public WechatOAuthStartResponse WechatState() => social.StartWechatOAuth(DeviceId());

    /// <summary>Sign in with a WeChat web OAuth code.</summary>
    /// <response code="200">The account this credential belongs to. Sign in at <c>/connect/token</c> next.</response>
    /// <response code="400">The state did not verify, or WeChat refused the code.</response>
    /// <response code="403">The account exists but is not active.</response>
    /// <response code="502">WeChat could not be reached.</response>
    [HttpPost("wechat/login")]
    [AllowAnonymous]
    [ProducesResponseType<SocialSignInResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status502BadGateway)]
    public Task<SocialSignInResponse> WechatLogin(
        WechatSignInRequest request,
        CancellationToken cancellationToken) =>
        // Decision 09: the DTO is the response, there is no envelope, and every failure bubbles to
        // AppExceptionHandler. No try/catch in here.
        social.SignInWithWechatAsync(request, cancellationToken);

    /// <summary>Sign in from the WeChat mini program, optionally redeeming a phone-number code.</summary>
    /// <response code="200">The account this credential belongs to.</response>
    /// <response code="400">WeChat refused the code.</response>
    /// <response code="403">The account exists but is not active.</response>
    /// <response code="502">WeChat could not be reached.</response>
    [HttpPost("wechat-mini/login")]
    [AllowAnonymous]
    [ProducesResponseType<SocialSignInResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status502BadGateway)]
    public Task<SocialSignInResponse> WechatMiniLogin(
        WechatMiniSignInRequest request,
        CancellationToken cancellationToken) =>
        social.SignInWithWechatMiniAsync(request, cancellationToken);

    /// <summary>Link a WeChat account to the signed-in account.</summary>
    /// <response code="204">Linked, or already linked to this same account.</response>
    /// <response code="400">The state did not verify, or WeChat refused the code.</response>
    /// <response code="409">That WeChat account is linked to a different account.</response>
    [HttpPost("wechat/bind")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> WechatBind(
        WechatSignInRequest request,
        CancellationToken cancellationToken)
    {
        await social.BindWechatAsync(currentUser.RequireConsumerId(), request, cancellationToken);

        // 204 rather than 200 with a body: binding is idempotent and there is nothing to report
        // that the linked-accounts endpoint does not already say.
        return NoContent();
    }

    /// <summary>Link a WeChat mini-program account to the signed-in account.</summary>
    [HttpPost("wechat-mini/bind")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> WechatMiniBind(
        WechatMiniSignInRequest request,
        CancellationToken cancellationToken)
    {
        await social.BindWechatMiniAsync(currentUser.RequireConsumerId(), request, cancellationToken);

        return NoContent();
    }

    // ------------------------------------------------------------------ LINE

    /// <summary>Start a LINE login flow.</summary>
    /// <response code="200">The channel id, scope, a signed state and the nonce to hand the LINE SDK.</response>
    [HttpGet("line/state")]
    [AllowAnonymous]
    [ProducesResponseType<LineOAuthStartResponse>(StatusCodes.Status200OK)]
    public LineOAuthStartResponse LineState() => social.StartLineOAuth(DeviceId());

    /// <summary>
    /// Sign in with a LINE id_token.
    /// </summary>
    /// <response code="200">The account this credential belongs to.</response>
    /// <response code="400">
    /// LINE would not verify the token, or the state did not verify. Both report
    /// <c>LINE_LOGIN_FAILED</c> - the LINE clients branch on that one code, so the state failure is
    /// deliberately not reported as <c>INVALID_STATE</c> the way the WeChat path reports it.
    /// </response>
    /// <response code="403">The account exists but is not active.</response>
    [HttpPost("line/login")]
    [AllowAnonymous]
    [ProducesResponseType<SocialSignInResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public Task<SocialSignInResponse> LineLogin(
        LineSignInRequest request,
        CancellationToken cancellationToken) =>
        social.SignInWithLineAsync(request, cancellationToken);

    /// <summary>Link a LINE account to the signed-in account.</summary>
    [HttpPost("line/bind")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> LineBind(LineSignInRequest request, CancellationToken cancellationToken)
    {
        await social.BindLineAsync(currentUser.RequireConsumerId(), request, cancellationToken);

        return NoContent();
    }

    // ------------------------------------------------------------------ Firebase

    /// <summary>
    /// Sign in with a Firebase ID token (Google, Apple or Facebook).
    /// </summary>
    /// <remarks>
    /// This is the one sign-in with two shapes of success. When the verified address already
    /// belongs to an account here, nothing is created and nothing is linked: the response carries
    /// <c>needsBindingConsent</c> and a signed <c>bindingToken</c>, and the client shows a consent
    /// screen and comes back to <c>firebase/confirm-binding</c>. Otherwise <c>account</c> is
    /// populated and the client goes to <c>/connect/token</c>.
    /// </remarks>
    /// <response code="200">Either a resolved account or a consent request; check <c>needsBindingConsent</c>.</response>
    /// <response code="400">The provider is missing or not enabled for this application.</response>
    /// <response code="401">The token is invalid, expired, for another project, or from another provider.</response>
    /// <response code="403">The account exists but is not active.</response>
    /// <response code="500">This deployment has no usable Firebase configuration.</response>
    /// <response code="502">Firebase could not be reached.</response>
    [HttpPost("firebase/login")]
    [AllowAnonymous]
    [ProducesResponseType<FirebaseSignInResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(StatusCodes.Status502BadGateway)]
    public Task<FirebaseSignInResponse> FirebaseLogin(
        FirebaseSignInRequest request,
        CancellationToken cancellationToken) =>
        social.SignInWithFirebaseAsync(request, cancellationToken);

    /// <summary>Answer the consent screen that <c>firebase/login</c> asked for.</summary>
    /// <response code="200"><c>confirmed</c> with the account, or <c>canceled</c> with nothing.</response>
    /// <response code="401">The binding token is forged, expired, or not a binding token.</response>
    /// <response code="403">The target account is not active.</response>
    /// <response code="409">The Firebase identity is linked to a different account.</response>
    [HttpPost("firebase/confirm-binding")]
    [AllowAnonymous]
    [ProducesResponseType<ConfirmFirebaseBindingResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public Task<ConfirmFirebaseBindingResponse> ConfirmFirebaseBinding(
        ConfirmFirebaseBindingRequest request,
        CancellationToken cancellationToken) =>
        social.ConfirmFirebaseBindingAsync(request, cancellationToken);

    /// <summary>Link a Firebase account to the signed-in account. No consent screen - the session is the consent.</summary>
    [HttpPost("firebase/bind")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> FirebaseBind(
        FirebaseSignInRequest request,
        CancellationToken cancellationToken)
    {
        await social.BindFirebaseAsync(currentUser.RequireConsumerId(), request, cancellationToken);

        return NoContent();
    }

    // ------------------------------------------------------------------ unbind

    /// <summary>
    /// Unlink a third-party account from the signed-in account.
    /// </summary>
    /// <remarks>
    /// The row is retired rather than deleted, so the provider account can later be linked
    /// elsewhere while the history of it having been here survives. The request is refused when it
    /// would remove the account's only way to sign in.
    /// </remarks>
    /// <param name="identityType"><c>WECHAT</c>, <c>WECHAT_MINI</c>, <c>FIREBASE</c> or <c>LINE</c>.</param>
    /// <param name="provider">
    /// Which application or sign-in provider inside that type - <c>miniprogram</c>,
    /// <c>google.com</c>. Omitted means the one with no provider, which is how web WeChat and LINE
    /// identities are stored.
    /// </param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <response code="204">Unlinked.</response>
    /// <response code="400">That identity type is not unlinked through this endpoint.</response>
    /// <response code="404">No such identity on this account.</response>
    /// <response code="409">It is the only way to sign in to this account.</response>
    [HttpDelete("{identityType}/bind")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Unbind(
        string identityType,
        [FromQuery] string? provider,
        CancellationToken cancellationToken)
    {
        await social.UnbindAsync(
            currentUser.RequireConsumerId(),
            identityType,
            provider ?? SocialProviders.None,
            cancellationToken);

        return NoContent();
    }

    /// <summary>
    /// Read leniently: absent means an empty device id inside the state, not a refusal. A browser
    /// redirect carries no device header, and refusing here would make web OAuth impossible while
    /// protecting nothing - the state's security is its signature.
    /// </summary>
    private string DeviceId() => HttpContext.Request.Headers[DeviceIdHeader].ToString();
}
