namespace UserSvc.Application.Ports.Tenancy;

/// <summary>
/// What the product master data says about one tenant.
/// <para>
/// <c>Usable</c> says whether this is still a place anyone may enter: an ACTIVE company, or a
/// supplier that exists and is approved. <c>Name</c> carries localized display names by locale tag,
/// and is empty when unknown - the front end then renders the code, which beats inventing a name.
/// </para>
/// </summary>
public sealed record TenantMasterDataEntry(
    string TenantType,
    string TenantCode,
    bool Usable,
    IReadOnlyDictionary<string, string> Name);

/// <summary>
/// The product master data, as tenancy consults it.
/// <para>
/// <b>Fail open.</b> Every caller treats a null result as "no opinion" and carries on. This gate
/// exists to keep people out of a tenant that has been switched off; it is not the authorization
/// boundary - that is the member row plus the permission codes - and a master-data outage must not
/// lock the whole platform out of every tenant at once.
/// </para>
/// </summary>
public interface ITenantMasterDataDirectory
{
    /// <returns>One entry per requested code, or null if the master data could not be reached.</returns>
    Task<IReadOnlyList<TenantMasterDataEntry>?> ValidateAsync(
        IReadOnlyCollection<string> companyCodes,
        IReadOnlyCollection<string> supplierCodes,
        CancellationToken cancellationToken);
}
