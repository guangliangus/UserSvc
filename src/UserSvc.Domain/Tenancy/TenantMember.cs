namespace UserSvc.Domain.Tenancy;

/// <summary>
/// One person's membership of one tenant - a company or a supplier - in the back office.
/// <para>
/// <b>Deliberately flat</b> (decision 04): the rules that matter here are orchestration rules
/// (who may write this row, whether the last administrator may be demoted, whether a role fits
/// the tenant's category), and every one of them needs to read other rows to answer. An aggregate
/// cannot protect an invariant it cannot see, so the guards live in the application service and
/// this type stays a record of what the row says.
/// </para>
/// <para>
/// The one thing worth knowing before touching it: <see cref="ScopeAll"/> and
/// <see cref="TenantCode"/> are not independent. A scope-all row means "every tenant in this
/// dimension" and parks <see cref="TenantScopes.ScopeAllSentinelCode"/> in the code column; any
/// lookup by code must exclude those rows first.
/// </para>
/// </summary>
public sealed class TenantMember
{
    public int Id { get; set; }

    /// <summary>The back-office account this membership belongs to (<c>iam.backend_users.id</c>).</summary>
    public int UserId { get; set; }

    /// <summary><see cref="TenantTypes.Company"/> or <see cref="TenantTypes.Supplier"/>.</summary>
    public string TenantType { get; set; } = TenantTypes.Company;

    /// <summary>The company or supplier code, or <see cref="TenantScopes.ScopeAllSentinelCode"/>
    /// when <see cref="ScopeAll"/> is set. A logical reference into the product master data; there
    /// is deliberately no foreign key, because that data lives in another service.</summary>
    public string TenantCode { get; set; } = string.Empty;

    /// <summary>
    /// Derived from the role bindings: true exactly when at least one bound role is an admin role.
    /// The application service keeps it in step on every write (G16) rather than letting it be set
    /// directly, so it always means the same thing - "this member holds an administrator role" -
    /// on every row, whole-dimension rows included.
    /// </summary>
    public bool IsAdmin { get; set; }

    /// <summary>Whole-dimension access: every company, or every supplier. See
    /// <see cref="TenantScopes"/> for why the boolean, not the code, is authoritative.</summary>
    public bool ScopeAll { get; set; }

    /// <summary>Free-text department label shown in the roster. Nullable in the live schema, and
    /// kept nullable here - existing rows are the constraint.</summary>
    public string? DeptName { get; set; }

    /// <summary>ACTIVE | DISABLED | REMOVED.</summary>
    public string Status { get; set; } = TenantMemberStatuses.Active;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public string? CreatedBy { get; set; }

    public string? UpdatedBy { get; set; }

    /// <summary>True when this row grants access to the named tenant of the named dimension -
    /// either by naming it, or by covering the whole dimension.</summary>
    public bool Covers(string tenantType, string tenantCode) =>
        Status == TenantMemberStatuses.Active
        && TenantType == tenantType
        && (ScopeAll || TenantCode == tenantCode);
}
