using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Api.Auth;
using UserSvc.Application.Features.BackOffice.SignIn;

namespace UserSvc.Api.Controllers.BackOffice;

/// <summary>
/// The two doors into the back office: a corporate mailbox with a password, and the corporate
/// one-time password.
/// <para>
/// <b>Neither returns a token, and that is the shape of this service rather than an omission.</b>
/// Credentials come out of <c>/connect/token</c> and nowhere else (decision 10) - the same
/// arrangement consumer registration and passkey sign-in already use. What these endpoints return
/// is a signed sign-in ticket plus everything the shell needs to draw itself: the contexts this
/// operator may enter, and - when there was only one and it was entered automatically - the
/// authority surface of it.
/// </para>
/// <para>
/// The client's next call is therefore <c>POST /connect/token</c> with
/// <c>grant_type=urn:usersvc:params:oauth:grant-type:back-office</c> and the ticket. When
/// <c>context_required</c> is true that mints a <b>pre-tenant</b> token, which reaches
/// <c>GET /back-office/tenants</c> and <c>POST /back-office/context</c> and nothing else; choosing a context is
/// then exchanged for a full back-office token through the second grant. See
/// <see cref="BackOfficeTokenIssuer"/> for why a scope is what expresses that distinction.
/// </para>
/// <para>
/// <b>Anonymous, and the error contract is the point of these being REST endpoints.</b> A locked-out
/// mailbox is a 429 with <c>Retry-After</c>, a non-corporate address on an internal account is a
/// 403 <c>INVALID_DOMAIN</c> naming the allow-list, an unreachable staff directory is a 502, and an
/// unconfigured one is a 500 <c>NOT_CONFIGURED</c> naming the section. At a token endpoint all four
/// would have to collapse into one <c>invalid_grant</c>, and a client could not tell an outage from
/// a typo.
/// </para>
/// </summary>
[ApiController]
[AllowAnonymous]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/back-office/auth")]
[Produces("application/json")]
public sealed class BackOfficeAuthController(BackOfficeSignInAppService signIns) : ControllerBase
{
    /// <summary>The header a gateway correlates a request across services with. It ends up on the
    /// audit row, so an operator can join "who signed in" to the request log.</summary>
    private const string RequestIdHeader = "X-Request-Id";

    /// <summary>Sign in with a corporate mailbox and a password.</summary>
    /// <remarks>
    /// An unknown address and a wrong password answer identically, on purpose: telling them apart
    /// turns this endpoint into a directory of which addresses have back-office accounts. The
    /// corporate domain rule is checked only after the password has verified, for the same reason.
    /// </remarks>
    [HttpPost("login")]
    [ProducesResponseType<BackOfficeSignInResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public Task<BackOfficeSignInResponse> SignIn(
        BackOfficePasswordSignInRequest request,
        CancellationToken cancellationToken) =>
        // Decision 09: success is the DTO itself and failures bubble to AppExceptionHandler, so
        // there is no try/catch and no envelope here.
        signIns.SignInWithPasswordAsync(request, RequestContext(), cancellationToken);

    /// <summary>Sign in with the corporate one-time password.</summary>
    /// <remarks>
    /// The client sends only an employee number and a code; the mailbox, the name and the
    /// department come from the HR record. A staff member with no back-office account yet is
    /// provisioned one from that record on their first successful sign-in - the corporate directory
    /// having just authenticated them is the same evidence an administrator would act on.
    /// </remarks>
    [HttpPost("otp-login")]
    [ProducesResponseType<BackOfficeSignInResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status502BadGateway)]
    public Task<BackOfficeSignInResponse> SignInWithStaffOtp(
        BackOfficeStaffOtpSignInRequest request,
        CancellationToken cancellationToken) =>
        signIns.SignInWithStaffOtpAsync(request, RequestContext(), cancellationToken);

    /// <summary>
    /// The request facts the audit trail records. Read here rather than inside the application
    /// service, which sees no HTTP - the same split <c>HttpContextCurrentUser</c> follows.
    /// </summary>
    private BackOfficeSignInContext RequestContext() => new(
        HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
        Request.Headers.UserAgent.ToString(),
        Request.Headers.TryGetValue(RequestIdHeader, out var header) && !string.IsNullOrWhiteSpace(header)
            ? header.ToString()
            : HttpContext.TraceIdentifier);
}
