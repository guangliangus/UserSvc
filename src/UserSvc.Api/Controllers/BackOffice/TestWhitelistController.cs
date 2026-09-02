using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.BackOffice.TestWhitelist;
using UserSvc.Application.Ports.Iam;

namespace UserSvc.Api.Controllers.BackOffice;

/// <summary>
/// The consumer test-user whitelist: which C-end accounts may additionally see, and order, the test
/// company's tour products.
/// <para>
/// <b>Deliberately no permission point on any route here.</b> The audience is the platform super
/// administrator alone, and a permission point granted to exactly one boolean flag is an
/// indirection with no payoff. Two things follow from using the flag directly instead: the guard
/// lives in the application service and reads <c>is_super_admin</c> from the account row, so
/// revoking that standing takes effect on the next request rather than at the next token refresh;
/// and no seeded code has to appear in already-issued tokens, so no administrator is locked out
/// until they sign in again.
/// </para>
/// <para>
/// Every change takes effect on the affected account's next request - the verdict is computed per
/// token validation rather than baked into an issued token - so nobody has to be signed out.
/// </para>
/// </summary>
[ApiController]
[Authorize(Policy = BackOfficePolicies.BackOffice)]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/back-office/test-whitelist")]
[Produces("application/json")]
public sealed class TestWhitelistController(
    TestWhitelistAppService whitelist, IBackOfficeCaller caller) : ControllerBase
{
    /// <summary>
    /// One page of the whitelist, ordered by consumer account id.
    /// <para>
    /// The bounds mirror the rest of the back office so the whole product shares one paging idiom;
    /// the list itself is expected to hold at most a couple of dozen accounts, so paging here is a
    /// convenience for the screen rather than a scale mechanism. An out-of-range page renders as an
    /// empty page rather than an error, and the page numbers in the response are the ones actually
    /// applied.
    /// </para>
    /// <para>
    /// An entry whose consumer account is gone is still listed, with <c>accountExists: false</c> -
    /// otherwise it would be invisible and therefore impossible to remove.
    /// </para>
    /// </summary>
    [HttpGet]
    [ProducesResponseType<TestWhitelistListResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public Task<TestWhitelistListResponse> List(
        CancellationToken cancellationToken,
        [FromQuery(Name = "page")] int page = 1,
        [FromQuery(Name = "page_size")] int pageSize = TestWhitelistPaging.DefaultPageSize) =>
        whitelist.ListAsync(caller, page, pageSize, cancellationToken);

    /// <summary>
    /// Put one consumer account on the whitelist. Idempotent.
    /// <para>
    /// The id must belong to an <c>identity.users</c> account that can still sign in: a missing,
    /// pending or disabled account is refused with 404. Use
    /// <c>GET /back-office/consumers/lookup</c> to resolve a phone number or an email address to an
    /// id first.
    /// </para>
    /// </summary>
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Add(
        [FromBody] AddTestWhitelistRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        await whitelist.AddAsync(caller, request.UserId, cancellationToken);
        return NoContent();
    }

    /// <summary>
    /// Take one consumer account off the whitelist. Idempotent - removing an id that is not on the
    /// list succeeds.
    /// <para>
    /// No existence check is applied against the consumer table, so an entry whose account is gone
    /// can still be cleaned up.
    /// </para>
    /// </summary>
    [HttpDelete("{userId:int}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Remove(int userId, CancellationToken cancellationToken)
    {
        await whitelist.RemoveAsync(caller, userId, cancellationToken);
        return NoContent();
    }
}
