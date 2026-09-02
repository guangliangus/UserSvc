namespace UserSvc.Domain.Tenancy;

/// <summary>
/// The two tenant dimensions a back-office user can belong to. Lowercase on the wire and in the
/// column, because the live <c>chk_tenant_members_type</c> check constraint spells them that way
/// and the back office compares them verbatim.
/// </summary>
public static class TenantTypes
{
    public const string Company = "company";

    public const string Supplier = "supplier";

    public static bool IsKnown(string? tenantType) =>
        tenantType is Company or Supplier;
}

/// <summary>
/// Membership lifecycle. Nothing here is ever deleted physically: <see cref="Removed"/> is the
/// soft delete, and re-adding the same person revives that very row rather than inserting a
/// second one - which is what the unique key on (user_id, tenant_type, tenant_code) requires.
/// </summary>
public static class TenantMemberStatuses
{
    public const string Active = "ACTIVE";

    public const string Disabled = "DISABLED";

    public const string Removed = "REMOVED";
}

/// <summary>
/// Whole-dimension access markers.
/// <para>
/// A member row with <see cref="TenantMember.ScopeAll"/> set means "every company" or "every
/// supplier", and its <c>tenant_code</c> carries <see cref="ScopeAllSentinelCode"/> as a
/// placeholder only. <b>The boolean is authoritative</b>: every query that matches on a code must
/// first exclude scope-all rows, or the literal <c>*</c> starts behaving like a real tenant code.
/// </para>
/// </summary>
public static class TenantScopes
{
    /// <summary>The placeholder written into <c>tenant_code</c> on a whole-dimension row.</summary>
    public const string ScopeAllSentinelCode = "*";
}
