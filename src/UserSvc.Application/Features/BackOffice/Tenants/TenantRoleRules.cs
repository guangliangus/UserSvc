namespace UserSvc.Application.Features.BackOffice.Tenants;

/// <summary>Role categories. The empty one is a real value, and it means "bindable nowhere".</summary>
public static class RoleCategories
{
    /// <summary>Left behind by the migration that introduced categories. Existing bindings that
    /// carry an uncategorised role are preserved, but no new one can be granted until an
    /// administrator files the role under a category.</summary>
    public const string None = "";

    public const string Platform = "platform";

    public const string Company = "company";

    public const string Supplier = "supplier";
}

/// <summary>Pure rules about which roles fit which tenant. No I/O, so no port (see the Ports rule
/// in docs/architecture.md).</summary>
public static class TenantRoleRules
{
    /// <summary>
    /// Whether a role of this category may be bound inside a tenant of this kind.
    /// <para>
    /// A supplier tenant takes supplier roles only. A company tenant takes company roles and the
    /// platform ones - the group's own staff work inside company contexts. Everything else,
    /// including an unknown tenant kind and an uncategorised role, is refused: the failure
    /// direction here is under-granting.
    /// </para>
    /// </summary>
    public static bool CategoryBindableTo(string category, string tenantType) => tenantType switch
    {
        Domain.Tenancy.TenantTypes.Supplier => category == RoleCategories.Supplier,
        Domain.Tenancy.TenantTypes.Company => category is RoleCategories.Platform or RoleCategories.Company,
        _ => false,
    };
}

/// <summary>Who owns a role. Only SYSTEM roles may carry service-level permission points.</summary>
public static class RoleOwnerTypes
{
    public const string System = "SYSTEM";

    public const string Company = "COMPANY";

    public const string Supplier = "SUPPLIER";
}

/// <summary>
/// Lifecycle states of the IAM catalogue rows - roles, menus and permission points.
/// <para>
/// Note the value: the live check constraints spell it <c>ACTIVE</c>. An older draft of the
/// porting notes says <c>ACTIVATED</c>, and a permission filter written against that spelling
/// matches nothing at all - which reads as "this role grants no permissions" rather than as an
/// error.
/// </para>
/// </summary>
public static class IamCatalogStatuses
{
    public const string Active = "ACTIVE";

    public const string Inactive = "INACTIVE";
}
