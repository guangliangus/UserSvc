namespace UserSvc.Domain.Iam;

/// <summary>
/// A permission point: the unit the request pipeline checks. It normally hangs off a menu, which is
/// what lets the back office render "menu -&gt; the things you can do on it" as one tree.
/// </summary>
public sealed class Permission
{
    public int Id { get; set; }

    public string Code { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    /// <summary>Grouping label for the catalogue page (uam, order, product, ...).</summary>
    public string Module { get; set; } = string.Empty;

    /// <summary>ACTIVE or INACTIVE. INACTIVE is the soft delete: it grants nothing anywhere, so
    /// every "what does this account actually hold" read filters it out.</summary>
    public string Status { get; set; } = PermissionStatuses.Active;

    public DateTimeOffset? CreatedAt { get; set; }

    public DateTimeOffset? UpdatedAt { get; set; }

    /// <summary>Owning menu. <b>Null = a service-level point</b> that never appears in the tenant
    /// permission tree - and, because of that, one only a platform (SYSTEM) role may be granted.</summary>
    public int? MenuId { get; set; }

    public bool IsActive() => Status == PermissionStatuses.Active;
}

/// <summary>Closed set behind <c>permissions_status_check</c>.</summary>
public static class PermissionStatuses
{
    public const string Active = "ACTIVE";
    public const string Inactive = "INACTIVE";

    public static bool IsValid(string? status) => status is Active or Inactive;
}
