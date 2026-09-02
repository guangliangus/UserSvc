using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.Registration;

namespace UserSvc.Api.Controllers;

/// <summary>
/// Sign-up. The only anonymous write endpoint in the service, and the one that decides who exists.
/// <para>
/// It issues no tokens: OpenIddict owns that (decision 10), so a client registers here and then
/// signs in at <c>/connect/token</c>. Two endpoints instead of one is the price of having exactly
/// one place that mints credentials.
/// </para>
/// </summary>
[ApiController]
[AllowAnonymous]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/auth/register")]
[Produces("application/json")]
public sealed class RegistrationController(RegistrationAppService registrations) : ControllerBase
{
    /// <summary>Create an account from a verified phone number or email address.</summary>
    /// <remarks>
    /// The verification ticket is single-use and is spent in the same transaction as the insert,
    /// so a failed registration leaves nothing behind - not the account, not a consumed ticket.
    /// </remarks>
    [HttpPost]
    [ProducesResponseType<RegisterResponse>(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<RegisterResponse>> Register(
        RegisterRequest request,
        CancellationToken cancellationToken)
    {
        // Decision 09: success is the DTO itself and failures bubble to AppExceptionHandler, so
        // there is no try/catch and no envelope here.
        var response = await registrations.RegisterAsync(request, cancellationToken);

        // 201, but deliberately without a Location header: the account it created is only readable
        // through /user/profile, which resolves "me" from the token the caller does not have yet.
        // A Location pointing at a 401 would be worse than none.
        return Created((string?)null, response);
    }
}
