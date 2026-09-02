namespace UserSvc.Domain.Iam;

/// <summary>
/// A role in the back-office catalogue: a named bundle of menu and permission grants that members
/// of a tenant can be bound to. <b>Flat by design</b> - the invariants that matter (delegation
/// ceiling, owner scoping, the menu cascade) span several tables and the caller's own standing, so
/// they are enforced by the application layer, not by this row.
/// <para>
/// Built-in versus custom is <see cref="OwnerType"/> alone: <c>SYSTEM</c> is a platform template,
/// <c>COMPANY</c>/<c>SUPPLIER</c> is a tenant's own role. The legacy <c>is_system</c> and
/// <c>is_admin_only</c> columns are gone; a second source of truth for the same fact is how they
/// drifted apart.
/// </para>
/// </summary>
public sealed class Role
{
    public int Id { get; set; }

    /// <summary>Stable handle. Immutable once created.</summary>
    public string Code { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    /// <summary>Nullable in the live schema; a role written before the description field existed
    /// carries NULL rather than an empty string.</summary>
    public string? Description { get; set; }

    /// <summary>Which kind of tenant the role is written for: platform / supplier / company.
    /// Empty means uncategorised - a legacy state that is bindable nowhere. Immutable after
    /// creation.</summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>Nullable in the live schema - rows predating the audit columns carry NULL.</summary>
    public DateTimeOffset? CreatedAt { get; set; }

    public DateTimeOffset? UpdatedAt { get; set; }

    public string? CreatedBy { get; set; }

    public string? UpdatedBy { get; set; }

    /// <summary>SYSTEM = platform built-in; COMPANY / SUPPLIER = a tenant's custom role.</summary>
    public string OwnerType { get; set; } = RoleOwnerTypes.System;

    /// <summary>The owning tenant's code. <b>Null, not empty</b>, for SYSTEM roles: the distinction
    /// is semantic - a SYSTEM role has no owner, it is not a role owned by a tenant whose code
    /// happens to be blank.</summary>
    public string? OwnerCode { get; set; }

    /// <summary>Administrator role (role-group leader): holders may manage members and create child
    /// roles inside their tenant. Settable only by the platform super administrator, and only on a
    /// SYSTEM role (chk_roles_admin_system).</summary>
    public bool IsAdmin { get; set; }

    /// <summary>
    /// Leader role of the owning role group; null = top level. The parent must have
    /// <see cref="IsAdmin"/> true.
    /// <para>
    /// This self-reference <b>is</b> the delegation tree. A holder of an administrator role may
    /// assign the roles in its subtree and nothing above or beside it, which is why the tree has to
    /// be walked in full (see <c>ListDescendants</c>) rather than one level at a time: the live
    /// catalogue is three deep (supplier_admin -&gt; product_supplier_admin -&gt; product_op).
    /// </para>
    /// </summary>
    public int? ParentRoleId { get; set; }

    /// <summary>True when the role belongs to a tenant rather than to the platform.</summary>
    public bool IsTenantOwned() =>
        OwnerType is RoleOwnerTypes.Company or RoleOwnerTypes.Supplier;

    /// <summary>True when this role is owned by exactly the given tenant.</summary>
    public bool IsOwnedBy(string tenantType, string tenantCode) =>
        OwnerType == RoleOwnerTypes.ForTenantType(tenantType)
        && OwnerCode is not null
        && OwnerCode == tenantCode;

    /// <summary>True when the role belongs to some <i>other</i> tenant than the one named.
    /// Platform (SYSTEM) roles are not "other" - they are everybody's.</summary>
    public bool IsOtherTenantRole(string tenantType, string tenantCode) =>
        IsTenantOwned() && !IsOwnedBy(tenantType, tenantCode);
}

/// <summary>Closed set behind <c>chk_roles_owner_type</c>.</summary>
public static class RoleOwnerTypes
{
    public const string System = "SYSTEM";
    public const string Company = "COMPANY";
    public const string Supplier = "SUPPLIER";

    /// <summary>supplier -&gt; SUPPLIER; everything else -&gt; COMPANY. The asymmetry is deliberate:
    /// company is the default tenant dimension, supplier the exception.</summary>
    public static string ForTenantType(string tenantType) =>
        string.Equals(tenantType, TenantTypes.Supplier, StringComparison.Ordinal)
            ? Supplier
            : Company;

    /// <summary>SUPPLIER -&gt; supplier; everything else -&gt; company.</summary>
    public static string ToTenantType(string ownerType) =>
        string.Equals(ownerType, Supplier, StringComparison.Ordinal)
            ? TenantTypes.Supplier
            : TenantTypes.Company;
}

/// <summary>Closed set behind <c>chk_roles_category</c>. The empty string is a legacy state that
/// is accepted by the database and rejected by every write path.</summary>
public static class RoleCategories
{
    public const string Unset = "";
    public const string Platform = "platform";
    public const string Supplier = "supplier";
    public const string Company = "company";

    /// <summary>The empty category is <b>not</b> valid input: it exists only as a legacy row state,
    /// and a role carrying it can be bound nowhere.</summary>
    public static bool IsValid(string? category) =>
        category is Platform or Supplier or Company;

    /// <summary>Which categories may be bound inside a tenant of this kind. Unknown tenant types
    /// resolve to nothing at all - fail closed.
    /// <para>
    /// A company tenant accepts <c>platform</c> as well as <c>company</c>, because the group-level
    /// functional roles are held by head-office staff who sit inside a company tenant.
    /// </para>
    /// </summary>
    public static IReadOnlyList<string> ForTenantType(string tenantType) => tenantType switch
    {
        TenantTypes.Supplier => [Supplier],
        TenantTypes.Company => [Platform, Company],
        _ => [],
    };

    /// <summary>Whether a role of this category may be bound in a tenant of this kind.</summary>
    public static bool BindableTo(string? category, string tenantType) =>
        category is not null && ForTenantType(tenantType).Contains(category);

    /// <summary>The category a tenant-owned role is pinned to. SYSTEM roles are free to pick any of
    /// the three - that is how the platform writes a template <i>for</i> suppliers.</summary>
    public static string PinnedFor(string ownerType) => ownerType switch
    {
        RoleOwnerTypes.Company => Company,
        RoleOwnerTypes.Supplier => Supplier,
        _ => Unset,
    };
}
