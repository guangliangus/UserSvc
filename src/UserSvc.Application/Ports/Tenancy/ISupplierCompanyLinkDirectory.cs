namespace UserSvc.Application.Ports.Tenancy;

/// <summary>
/// Which suppliers are mounted on which company. It is what makes a company context able to read
/// its suppliers' data, and a supplier context able to see the company it hangs off.
/// </summary>
public interface ISupplierCompanyLinkDirectory
{
    /// <summary>Active supplier codes mounted on a company.</summary>
    Task<IReadOnlyList<string>> ListSupplierCodesByCompanyAsync(
        string companyCode, CancellationToken cancellationToken);

    /// <summary>The company a supplier is mounted on, or null when it is independent - which is
    /// the conservative default, not an error.</summary>
    Task<string?> FindCompanyCodeBySupplierAsync(
        string supplierCode, CancellationToken cancellationToken);
}
