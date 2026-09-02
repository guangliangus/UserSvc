using Microsoft.Extensions.Logging;
using UserSvc.Application.Ports.Tenancy;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The stand-in for the supplier-to-company mounting table until slice 12 lands it. The real
/// adapter reads <c>supplier_company_links</c> - ACTIVE rows only, <c>ListActiveByCompany</c> and
/// <c>FindActiveBySupplier</c> - and that table does not exist in this database yet; a membership
/// row says who may enter a tenant, never which tenants hang off which, so there is nothing here to
/// derive it from.
/// <para>
/// <b>It answers the port's own conservative default - no mounted suppliers, no mounting company -
/// and does not throw.</b> An earlier version refused with 501 on the argument that "looked it up
/// and found nothing" and "never looked" must not be indistinguishable. That argument is sound
/// about this port in isolation and wrong about where the port sits. This is not a leaf of the
/// tenant-scope answer: <c>TenantContextAppService.ComputeAsync</c> is the single funnel that every
/// authority decision comes through, so a throw here did not degrade the data-scope envelope, it
/// took down the whole authority face - permissions, menus and roles - for every caller acting in a
/// company or supplier context. Measured against the live database: <c>POST /auth/context</c>, the
/// tenant roster, the menu tree and every member write answered 501, and <c>GET /back-office/me</c>
/// answered 200 with <c>menus: null</c>, which the shell reads as "this backend does not gate
/// menus". A refusal meant to fail closed was producing a fail-open one layer up.
/// </para>
/// <para>
/// The empty answer cannot widen anything, which is what makes it safe to give. A scope envelope is
/// data breadth, and every consumer of it treats an absent code as "not covered":
/// <c>CallerFacts.ScopeCoversOwnerCode</c> refuses an empty value set, and downstream services
/// filter rows to the codes named. So this degrades a company context to "sees itself and no
/// supplier" and a supplier context to "independent" - strictly less than the truth, never more,
/// and exactly what the spec prescribes when the link table has no row (09-tenant §3.2: supplier
/// NotFound yields an empty company side, "the conservative default, not an error").
/// </para>
/// <para>
/// It stays loud. Every call logs at Warning naming the code that could not be resolved, so an
/// operator reading the log sees narrowed envelopes rather than guessing at them, and swapping this
/// registration for the real adapter is still the whole cutover.
/// </para>
/// </summary>
public sealed class UnavailableSupplierCompanyLinkDirectory(
    ILogger<UnavailableSupplierCompanyLinkDirectory> logger) : ISupplierCompanyLinkDirectory
{
    public Task<IReadOnlyList<string>> ListSupplierCodesByCompanyAsync(
        string companyCode, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        logger.LogWarning(
            "No supplier-link adapter is configured, so company {CompanyCode} resolves to no "
            + "mounted suppliers. Its data scope is narrower than the truth until slice 12 lands.",
            companyCode);

        return Task.FromResult<IReadOnlyList<string>>([]);
    }

    public Task<string?> FindCompanyCodeBySupplierAsync(
        string supplierCode, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        logger.LogWarning(
            "No supplier-link adapter is configured, so supplier {SupplierCode} resolves as "
            + "independent. Its data scope carries no company until slice 12 lands.",
            supplierCode);

        return Task.FromResult<string?>(null);
    }
}
