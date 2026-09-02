using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.BackOffice.Consumers;
using UserSvc.Application.Ports.Iam;

namespace UserSvc.Api.Controllers.BackOffice;

/// <summary>
/// Resolving a consumer's contact detail to their account, so an operator holding a phone number or
/// an email address can find the id the test whitelist asks for.
/// <para>
/// <b>No permission point, for the same reason as the whitelist routes</b>: the audience is the
/// platform super administrator alone, and the guard is that flag read from the account row per
/// request rather than a seeded code.
/// </para>
/// <para>
/// <b>What an operator may search by, and see, is deliberately narrow.</b> The search is an exact
/// match on the blind index - consumer identifiers are stored encrypted and the only queryable
/// index over them is a deterministic HMAC - so there is no prefix or substring search to offer and
/// no way to browse the consumer base with this. What comes back are masked contact details, never
/// the plaintext: this is somebody reading another person's details, where recognition is the whole
/// requirement.
/// </para>
/// </summary>
[ApiController]
[Authorize(Policy = BackOfficePolicies.BackOffice)]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/back-office/consumers")]
[Produces("application/json")]
public sealed class ConsumerLookupController(
    ConsumerLookupAppService consumers, IBackOfficeCaller caller) : ControllerBase
{
    /// <summary>
    /// The consumer account behind one complete phone number or email address.
    /// <para>
    /// A partial value does not hash to the stored index, so it comes back as 404 rather than as a
    /// near miss. So does an address that belongs to an account whose consumer row is gone: the
    /// point of this endpoint is to let an operator verify an account before whitelisting it, and a
    /// bare id verifies nothing.
    /// </para>
    /// </summary>
    /// <param name="identityType"><c>phone</c> or <c>email</c>.</param>
    /// <param name="identifier">The complete contact detail, normalized exactly as registration
    /// normalizes it before hashing.</param>
    /// <param name="cancellationToken">Cancels the reads.</param>
    [HttpGet("lookup")]
    [ProducesResponseType<ConsumerSummaryResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public Task<ConsumerSummaryResponse> Lookup(
        CancellationToken cancellationToken,
        [FromQuery(Name = "identity_type")] string? identityType = null,
        [FromQuery(Name = "identifier")] string? identifier = null) =>
        consumers.LookupAsync(caller, identityType, identifier, cancellationToken);
}
