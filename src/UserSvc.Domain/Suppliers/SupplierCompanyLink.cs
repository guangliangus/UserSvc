namespace UserSvc.Domain.Suppliers;

/// <summary>
/// One supplier mounted onto one company.
/// <para>
/// <b>The mounting is data scope.</b> Every member of the company is handed the suppliers mounted
/// onto it, and every member of the supplier is handed the company it hangs under; both end up in
/// the access token's scope envelope and are trusted downstream. So an unmount is a revocation, not
/// a bookkeeping change, and the write path has to retire the tokens that still carry it.
/// </para>
/// <para>
/// <b>Deliberately flat</b> (decision 04). The one invariant worth protecting - at most one ACTIVE
/// mounting per supplier - is protected by the partial unique index
/// <c>uk_supplier_links_active</c>, which is the only place that can hold it against two concurrent
/// writers. A guard in this class would be a second, weaker opinion about the same rule.
/// </para>
/// <para>
/// <c>supplier_code</c> and <c>company_code</c> are logical references into the product master data
/// (<c>pim.suppliers.code</c> / <c>pim.companies.code</c>), which lives in another service. There is
/// no foreign key behind either, and the codes are validated over the master-data port on the write
/// path instead.
/// </para>
/// </summary>
public sealed class SupplierCompanyLink
{
    public int Id { get; set; }

    public string SupplierCode { get; set; } = string.Empty;

    public string CompanyCode { get; set; } = string.Empty;

    /// <summary>See <see cref="SupplierCompanyLinkStatuses"/>.</summary>
    public string Status { get; set; } = SupplierCompanyLinkStatuses.Active;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public string CreatedBy { get; set; } = string.Empty;

    public string UpdatedBy { get; set; } = string.Empty;
}

/// <summary>
/// Statuses of a supplier-to-company mounting.
/// <para>
/// <see cref="Unlinked"/> rows are kept as history - the unmount is soft. At most one
/// <see cref="Active"/> row exists per supplier, and that is enforced by the partial unique index
/// rather than by application code.
/// </para>
/// </summary>
public static class SupplierCompanyLinkStatuses
{
    public const string Active = "ACTIVE";

    public const string Unlinked = "UNLINKED";

    public static bool IsKnown(string? status) => status is Active or Unlinked;
}

/// <summary>
/// The audit vocabulary this slice writes, which the shared IAM catalogue does not carry yet.
/// <para>
/// <b>It should not stay here.</b> <c>UserSvc.Domain.Iam.IamAuditActions</c> and
/// <c>IamAuditTargetTypes</c> are the catalogue for everything else IAM records, and a second list
/// of action names is how two spellings of one action end up in the same column. These live here
/// only because that type belongs to another slice's files; folding them in is a move, not a change
/// - the stored value is the same string either way. The precedent is
/// <c>BackOfficeAuditActions.SelfPasswordReset</c>, which is parked in its own slice for the same
/// reason.
/// </para>
/// </summary>
public static class SupplierLinkAuditVocabulary
{
    /// <summary>A supplier was mounted onto a company, or moved from one company to another. A
    /// relink records one row, not two: what changed is the mounting, and the previous company is
    /// recoverable from the UNLINKED row it left behind.</summary>
    public const string LinkAction = "SUPPLIER_LINK";

    /// <summary>A supplier's mounting was retired. Never written when there was nothing to
    /// retire.</summary>
    public const string UnlinkAction = "SUPPLIER_UNLINK";

    /// <summary>The audit target kind. The target id is the supplier code, not the row id: the row
    /// is an implementation detail and the code is what an operator searches by.</summary>
    public const string TargetType = "supplier_link";
}
