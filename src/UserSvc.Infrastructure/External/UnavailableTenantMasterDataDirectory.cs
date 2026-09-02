using Microsoft.Extensions.Logging;
using UserSvc.Application.Ports.Tenancy;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The stand-in for the product master data until an adapter for it exists. The real one would read
/// the company and supplier registers - is this company ACTIVE, does this supplier exist and is it
/// approved, what is its display name in each locale - from the PIM service, which owns those
/// tables. Nothing in this service holds them: <c>iam.tenant_members.tenant_code</c> is a logical
/// reference with deliberately no foreign key behind it, precisely because the referenced rows live
/// somewhere else.
/// <para>
/// <b>It answers null, and null is a refusal rather than an invention.</b> This port already has a
/// vocabulary for "could not be reached" - it is what the nullable return means - and every caller
/// is written to treat it as "no opinion" and carry on. So answering null says exactly the true
/// thing: nobody was asked. Returning an entry list would be the fabrication, because each entry
/// carries a <c>Usable</c> verdict this component cannot compute, and a fabricated <c>true</c> would
/// wave people into tenants that have been switched off while a fabricated <c>false</c> would lock
/// everyone out of every tenant at once.
/// </para>
/// <para>
/// Throwing is the wrong shape here even though it is right for the staff directory. This gate is
/// not the authorization boundary - the membership row and the permission codes are - and the port
/// documents it as fail-open for that reason. A 501 would take the whole back-office context
/// selection down to enforce a check that is, by construction, advisory.
/// </para>
/// </summary>
public sealed class UnavailableTenantMasterDataDirectory(
    ILogger<UnavailableTenantMasterDataDirectory> logger) : ITenantMasterDataDirectory
{
    public Task<IReadOnlyList<TenantMasterDataEntry>?> ValidateAsync(
        IReadOnlyCollection<string> companyCodes,
        IReadOnlyCollection<string> supplierCodes,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Debug, not warning. This runs on every context listing and every context switch, so a
        // per-call warning would be pure noise in a deployment that is knowingly without the
        // upstream; the fact that no adapter is configured is a deployment property, visible once
        // at startup in the registration, not news on each request.
        logger.LogDebug(
            "Tenant master data was consulted for {CompanyCount} company and {SupplierCount} "
            + "supplier codes, but no master-data adapter is configured. Reporting 'not reached' so "
            + "the callers fall open.",
            companyCodes.Count,
            supplierCodes.Count);

        return Task.FromResult<IReadOnlyList<TenantMasterDataEntry>?>(null);
    }
}
