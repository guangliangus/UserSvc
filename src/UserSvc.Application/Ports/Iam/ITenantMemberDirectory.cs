namespace UserSvc.Application.Ports.Iam;

/// <summary>
/// The window onto tenant membership that role management needs. The rows belong to the tenant
/// slice - this is a read-mostly view of them, expressed in this module's own record type so the
/// two contexts stay decoupled.
/// <para>
/// It is a port because there is a database on the other side, and because every guard in this
/// module has to be testable without one.
/// </para>
/// </summary>
public interface ITenantMemberDirectory
{
    /// <summary>ACTIVE memberships only. This is the authority for what an account can currently
    /// do; disabled rows grant nothing.</summary>
    Task<IReadOnlyList<TenantMembershipRow>> ListActiveByUserAsync(
        int userId,
        CancellationToken cancellationToken);

    /// <summary>
    /// ACTIVE and DISABLED, but not REMOVED. Read paths need the disabled ones: a member switched
    /// off inside a tenant is exactly the row an administrator opens ("why is this off, and what
    /// did they have?"), and hiding it makes the detail page read as "belongs to nothing".
    /// </summary>
    Task<IReadOnlyList<TenantMembershipRow>> ListNonRemovedByUserAsync(
        int userId,
        CancellationToken cancellationToken);

    Task<TenantMembershipRow?> FindAsync(
        int userId,
        string tenantType,
        string tenantCode,
        CancellationToken cancellationToken);

    /// <summary>Active administrators of one tenant, for the last-administrator guard.</summary>
    Task<int> CountActiveAdminsAsync(
        string tenantType,
        string tenantCode,
        CancellationToken cancellationToken);

    /// <summary>Set the derived administrator flag on one membership row.</summary>
    Task SetAdminAsync(int memberId, bool isAdmin, CancellationToken cancellationToken);
}

/// <summary>
/// One membership as this module reads it.
/// <para>
/// <c>ScopeAll</c> marks a whole-dimension membership: its tenant code is the <c>*</c> sentinel and
/// it grants breadth over every tenant of that type. Breadth is never authority - such a row is not
/// a candidate to own a role.
/// </para>
/// <para>
/// <c>IsAdmin</c> is derived, never authored: "this membership binds an administrator role". It
/// carries no claim about <i>which</i> tenant, which is why every last-administrator check filters by
/// tenant as well.
/// </para>
/// </summary>
public sealed record TenantMembershipRow(
    int Id,
    int UserId,
    string TenantType,
    string TenantCode,
    bool IsAdmin,
    bool ScopeAll,
    string? DeptName,
    string Status);
