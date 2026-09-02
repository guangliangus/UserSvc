using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Features.BackOffice.Suppliers;
using UserSvc.Application.Ports.Iam;

namespace UserSvc.Api.Controllers.BackOffice;

/// <summary>
/// Which approved suppliers hang off which company.
/// <para>
/// The permission point each route expects is named on the action and asserted inside the
/// application service, which is where the rest of this module puts it: the point is resolved from
/// the authority snapshot rather than from the token, so a permission taken away lands on the next
/// request rather than at the holder's next sign-in.
/// </para>
/// <para>
/// <b>Two things gate every route here</b>, not one. The permission code is the first, and the
/// caller's acting context is the second: a session acting as one company or one supplier is
/// refused whatever codes it holds. Both points are seeded against the platform-audience "approved
/// suppliers" menu, but the audience rule that would keep that menu off a tenant-owned role is
/// switched off service-wide, so the code alone does not establish that the holder is on the
/// platform plane. PLATFORM and GLOBAL pass - a whole-dimension operator legitimately administers
/// mountings across their dimension.
/// </para>
/// </summary>
[ApiController]
[Authorize(Policy = BackOfficePolicies.BackOffice)]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/back-office")]
[Produces("application/json")]
public sealed class SupplierLinkController(
    SupplierLinkAppService suppliers, IBackOfficeCaller caller) : ControllerBase
{
    /// <summary>
    /// The mounting, administrators and active member count of each requested supplier. Requires
    /// <c>uam.supplier_link.read</c>.
    /// <para>
    /// <c>supplier_codes</c> is comma-joined. With <c>company_code</c> alone, the suppliers mounted
    /// onto that company are listed instead; with both, the supplier set is narrowed to those
    /// mounted onto that company. With neither, the answer is an empty list - this endpoint does not
    /// dump every mounting on the platform.
    /// </para>
    /// <para>
    /// No master-data call happens on this path, so it cannot answer 502.
    /// </para>
    /// </summary>
    [HttpGet("supplier-links")]
    [ProducesResponseType<SupplierLinkListResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public Task<SupplierLinkListResponse> List(
        CancellationToken cancellationToken,
        [FromQuery(Name = "supplier_codes")] string? supplierCodes = null,
        [FromQuery(Name = "company_code")] string? companyCode = null) =>
        suppliers.ListAsync(
            caller, SupplierCodes.Split(supplierCodes), companyCode, cancellationToken);

    /// <summary>
    /// Mount, move or unmount one supplier. Requires <c>uam.supplier_link.manage</c>.
    /// <para>
    /// A non-null <c>company_code</c> mounts - or relinks - the supplier onto that company after a
    /// live master-data validation: the supplier must exist and be approved, and the company must
    /// exist and be active. A null, omitted or blank one unmounts, and does so idempotently.
    /// </para>
    /// <para>
    /// The business failures are real status codes rather than a soft envelope, and each reason has
    /// its own code: 400 <c>SUPPLIER_NOT_FOUND</c> (the master data has never heard of this
    /// supplier) and 400 <c>COMPANY_NOT_FOUND</c> (no such company, or one that is not active - one
    /// code for both, deliberately), 422 <c>SUPPLIER_NOT_APPROVED</c> (a real supplier whose state
    /// forbids the mounting - the request is fine, so no edit to it helps), 409
    /// <c>SUPPLIER_ALREADY_LINKED</c> (already where you asked for), and 502
    /// <c>UPSTREAM_SERVICE_UNAVAILABLE</c> when the master data cannot be reached - the one case
    /// where nothing was written and retrying later is right.
    /// </para>
    /// <para>
    /// Two of those statuses differ from the numbers the Go service put inside its always-200
    /// envelope (400 for the unapproved supplier, 503 for the unreachable master data). The
    /// <c>errorCode</c> - which is what the Go clients branched on, since they only ever saw HTTP
    /// 200 for the first - is identical in every case. 422 says "the request is not the problem",
    /// and 502 is what this whole service answers when an upstream fails; 503 would claim this
    /// service is the one that is unavailable.
    /// </para>
    /// </summary>
    [HttpPut("suppliers/{code}/link")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(StatusCodes.Status502BadGateway)]
    public async Task<IActionResult> UpdateLink(
        string code,
        [FromBody] UpdateSupplierLinkRequest request,
        CancellationToken cancellationToken)
    {
        await suppliers.UpdateLinkAsync(caller, code, request, cancellationToken);
        return NoContent();
    }
}
