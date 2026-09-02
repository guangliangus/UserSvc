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
/// Both points are seeded against the platform-audience "approved suppliers" menu, so in practice
/// only a platform role carries them. The gate is still the code and not the caller's acting
/// context - a whole-dimension operator legitimately holds it, and the code is the one thing that
/// says so.
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
    /// The business failures are real status codes rather than a soft envelope: 400
    /// <c>SUPPLIER_NOT_FOUND</c> / <c>COMPANY_NOT_FOUND</c> (fix the code), 422
    /// <c>SUPPLIER_NOT_APPROVED</c> (the supplier's state is wrong, not the request), 409
    /// <c>SUPPLIER_ALREADY_LINKED</c> (already where you asked for), and 502 when the master data
    /// cannot be reached - the one case where nothing was written and retrying later is right.
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
