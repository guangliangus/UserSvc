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
/// vocabulary for "could not be reached" - it is what the nullable return means - so answering null
/// says exactly the true thing: nobody was asked. Returning entries would be the fabrication,
/// because each entry carries a <see cref="TenantMasterDataEntry.Verdicts"/> this component cannot
/// compute. Neither of the three verdicts is safe to invent: a fabricated
/// <see cref="TenantMasterDataEntry.Verdicts.Usable"/> would wave people into tenants that have been
/// switched off and let a supplier be mounted onto a company nobody has confirmed exists, while a
/// fabricated <see cref="TenantMasterDataEntry.Verdicts.Unknown"/> or
/// <see cref="TenantMasterDataEntry.Verdicts.NotUsable"/> would lock everyone out of every tenant at once
/// <i>and</i> report a specific, wrong reason for it - "no such supplier" about a supplier that may
/// well exist.
/// </para>
/// <para>
/// <b>Null is also what keeps the mounting write failing closed</b>, which is the half that matters
/// most here. Spec 12 section 3.1.4 step 1 requires the mount path to refuse when the master data
/// cannot be consulted, and <c>SupplierLinkAppService</c> does exactly that on null: 502, nothing
/// written. The tenancy reads fall open on the same null. One value, two correct behaviours,
/// because the callers - not the placeholder - are where the direction is decided.
/// </para>
/// <para>
/// Throwing is the wrong shape here even though it is right for a missing OTP provider. The read
/// side of this gate is not the authorization boundary - the membership row and the permission
/// codes are - so a 501 would take back-office context selection down to enforce a check that is,
/// on that path, advisory.
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
            + "supplier codes, but no master-data adapter is configured. Reporting 'not reached': "
            + "the tenancy reads fall open on that, and a supplier mounting refuses.",
            companyCodes.Count,
            supplierCodes.Count);

        return Task.FromResult<IReadOnlyList<TenantMasterDataEntry>?>(null);
    }
}
