namespace UserSvc.Application.Features.BackOffice.Suppliers;

/// <summary>
/// An administrator of a supplier tenant, as the mounting page shows them.
/// </summary>
public sealed record SupplierLinkAdminResponse
{
    public required int UserId { get; init; }

    /// <summary>Empty when the account is gone - the membership row outlives it, and a blank name
    /// beside a live id is the honest rendering of that.</summary>
    public string Nickname { get; init; } = string.Empty;

    /// <summary>Empty when the account holds no email identity, or when its stored address cannot
    /// be read back.</summary>
    public string Email { get; init; } = string.Empty;
}

/// <summary>
/// One supplier's mounting relationship, plus who administers it and how many people are in it.
/// </summary>
public sealed record SupplierLinkResponse
{
    public required string SupplierCode { get; init; }

    /// <summary><b>Null</b> - not an empty string - when the supplier is independent, meaning it has
    /// no ACTIVE mounting. The distinction is what lets the front end tell "not mounted" from
    /// "mounted onto a company whose code we failed to read".</summary>
    public string? CompanyCode { get; init; }

    /// <summary>
    /// The first administrator, kept for callers written before a supplier could have several. Null
    /// when it has none. <see cref="Admins"/> is the authoritative field.
    /// </summary>
    public SupplierLinkAdminResponse? Admin { get; init; }

    /// <summary>
    /// Every ACTIVE administrator of the supplier tenant; empty when it has none. This is the
    /// authoritative field - a supplier may have several administrators since the one-administrator
    /// unique index was dropped.
    /// </summary>
    public IReadOnlyList<SupplierLinkAdminResponse> Admins { get; init; } = [];

    /// <summary>ACTIVE members of the supplier tenant. Zero when it has none.</summary>
    public required int MemberCount { get; init; }
}

/// <summary>One item per requested supplier code, in the order they were requested.</summary>
public sealed record SupplierLinkListResponse
{
    /// <summary>Never null. Empty when nothing matched, and when neither a supplier nor a company
    /// filter was given - an unfiltered listing of every mounting is not something this endpoint
    /// offers.</summary>
    public IReadOnlyList<SupplierLinkResponse> Items { get; init; } = [];
}

/// <summary>
/// Mount or unmount one supplier.
/// <para>
/// A non-null <see cref="CompanyCode"/> mounts - or moves - the supplier onto that company. A null,
/// omitted, empty or whitespace-only value unmounts it. There is no separate delete route because
/// there is nothing to delete: the unmount is a status change on the row.
/// </para>
/// </summary>
public sealed record UpdateSupplierLinkRequest
{
    public string? CompanyCode { get; init; }
}

/// <summary>
/// The permission points the mounting endpoints require.
/// <para>
/// Both are seeded against the "approved suppliers" menu, whose audience is the platform, so in
/// practice only a platform role carries them. The gate is still the permission code and not the
/// caller's acting context: a whole-dimension operator legitimately holds it, and the code is the
/// one thing that says so.
/// </para>
/// </summary>
public static class SupplierLinkPermissions
{
    public const string Read = "uam.supplier_link.read";

    public const string Manage = "uam.supplier_link.manage";
}

/// <summary>
/// How a comma-joined list of tenant codes off a query string becomes a code list.
/// <para>
/// Pure computation, so not a port; separate from the service so the emptiness rules - which decide
/// whether the endpoint answers "nothing matched" or "here is the whole company" - are testable on
/// their own.
/// </para>
/// </summary>
public static class SupplierCodes
{
    /// <summary>
    /// Splits on commas, trims each entry, drops the empties and deduplicates, <b>preserving the
    /// order the caller gave</b>. The order matters: it is the order of the response items, so a
    /// screen can line them up against the list it already has.
    /// </summary>
    public static IReadOnlyList<string> Split(string? commaJoined) =>
        Normalize((commaJoined ?? string.Empty).Split(','));

    /// <summary>The same rules applied to an already-split list.</summary>
    public static IReadOnlyList<string> Normalize(IEnumerable<string>? codes)
    {
        if (codes is null)
        {
            return [];
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);

        return
        [
            .. codes
                .Select(code => (code ?? string.Empty).Trim())
                .Where(code => code.Length > 0 && seen.Add(code))
        ];
    }
}
