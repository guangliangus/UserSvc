namespace UserSvc.Domain.Iam;

/// <summary>The two tenant dimensions. Anything else fails closed.</summary>
public static class TenantTypes
{
    public const string Company = "company";
    public const string Supplier = "supplier";

    /// <summary>Fixed order, so a scope envelope serialises byte-identically no matter which path
    /// produced it.</summary>
    public static readonly IReadOnlyList<string> All = [Supplier, Company];

    public static bool IsAllowed(string? tenantType) =>
        tenantType is Supplier or Company;
}

/// <summary>The act (acting context) a back-office token carries.</summary>
public static class ActTypes
{
    public const string Platform = "PLATFORM";
    public const string Company = "COMPANY";
    public const string Supplier = "SUPPLIER";

    /// <summary>A whole-dimension context: every company, or every supplier. Not the platform -
    /// this is where every <c>scope_all</c> holder lands.</summary>
    public const string Global = "GLOBAL";
}

/// <summary>Values that are load-bearing in more than one place.</summary>
public static class IamConstants
{
    /// <summary>The tenant code of a whole-dimension membership row. It is a sentinel, never a
    /// tenant: a role owned by <c>*</c> would match no tenant's delegable set while looking like
    /// it should.</summary>
    public const string ScopeAllSentinelCode = "*";

    /// <summary>The menu a role must carry to be a <i>role</i> administrator rather than merely a
    /// member administrator.</summary>
    public const string MenuCodeUserRoles = "user-roles";

    /// <summary>The permission point that pairs with <see cref="MenuCodeUserRoles"/> to open the
    /// role-management gate. Both must sit on the <b>same</b> role.</summary>
    public const string PermissionCodeRoleManage = "uam.role.manage";

    /// <summary>The point that opens every "who is in this tenant, and what do they hold" read. It
    /// is the second key that opens the menu tree, because a grant payload is unreadable without the
    /// names of the menus it points at.</summary>
    public const string PermissionCodeMemberRead = "uam.member.read";

    /// <summary>Reserved on purpose: a tenant role coded <c>admin</c> can no longer escalate
    /// anything, but it still reads to a human as "the platform administrator".</summary>
    public const string RoleCodeAdmin = "admin";

    /// <summary>Walk limit for the ancestor chain in parent validation. A corrupted parent chain
    /// must not spin.</summary>
    public const int MaxRoleAncestorDepth = 16;

    /// <summary>Depth limit of the recursive CTE behind <c>ListDescendants</c>.</summary>
    public const int MaxRoleSubtreeDepth = 16;
}

/// <summary>
/// One dimension of a caller's data-scope envelope. <see cref="IsGlobal"/> and
/// <see cref="Values"/> are not alternatives to each other in the wire shape: a global claim still
/// carries an empty (never null) list, so a consumer reads "granted everything" rather than
/// "granted nothing".
/// </summary>
public sealed record ScopeClaim(IReadOnlyList<string> Values, bool IsGlobal)
{
    public static ScopeClaim Empty { get; } = new([], false);

    public static ScopeClaim Global { get; } = new([], true);
}

/// <summary>A menu the caller may route to. Carried by the authz face for the front-end shell.</summary>
public sealed record MenuRoute(int Id, string Code, string? Path);

/// <summary>
/// Statuses of a tenant membership.
/// <para>
/// REMOVED is a retirement, not a deletion: the row and the role bindings on it stay, so an account
/// re-added later is visibly the same account rather than a new one, and the audit trail still lines
/// up. Read paths accept DISABLED and refuse REMOVED; write paths accept only ACTIVE.
/// </para>
/// </summary>
public static class TenantMembershipStatuses
{
    public const string Active = "ACTIVE";
    public const string Disabled = "DISABLED";
    public const string Removed = "REMOVED";
}

/// <summary>Statuses of a back-office account, as IAM reads them.</summary>
public static class BackOfficeUserStatuses
{
    public const string Pending = "PENDING";
    public const string Active = "ACTIVE";
    public const string Disabled = "DISABLED";
}
