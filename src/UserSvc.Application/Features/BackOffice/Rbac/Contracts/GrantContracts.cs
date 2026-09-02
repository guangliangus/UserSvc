namespace UserSvc.Application.Features.BackOffice.Rbac.Contracts;

/// <summary>
/// What a role (or an account) effectively grants. All four lists are always present, never null.
/// <para>
/// The same shape serves "this role" and "this person" on purpose: a user detail page renders what
/// somebody can reach with the very tree that renders one role, instead of one being a tree and the
/// other a pile of flat badges.
/// </para>
/// </summary>
public sealed record RoleGrantsResponse
{
    public IReadOnlyList<int> MenuIds { get; init; } = [];

    public IReadOnlyList<string> MenuCodes { get; init; } = [];

    public IReadOnlyList<int> PermissionIds { get; init; } = [];

    public IReadOnlyList<string> PermissionCodes { get; init; } = [];
}

/// <summary>Replace a role's menu and permission grants.</summary>
public sealed record SaveRoleGrantsRequest
{
    public IReadOnlyList<string> MenuCodes { get; init; } = [];

    public IReadOnlyList<string> PermissionCodes { get; init; } = [];

    /// <summary>
    /// Re-sign every bound member's session even though nothing was taken away. Rarely needed: a
    /// change that removes anything converges on its own, and a purely additive one arrives on the
    /// next natural refresh.
    /// </summary>
    public bool ForceReissue { get; init; }
}

/// <summary>The legacy permissions-only editor. It derives the owning menu closure and then goes
/// through the same guarded path as the full grant editor.</summary>
public sealed record UpdateRolePermissionsRequest
{
    public IReadOnlyList<string> PermissionCodes { get; init; } = [];
}

/// <summary>
/// Why a set of grants was refused, one bucket per rule. Every list is empty unless that particular
/// rule fired, so the form can mark exactly the offending chips.
/// </summary>
public sealed record RoleGrantViolations
{
    /// <summary>Menu codes that match no ACTIVE menu. A soft-deleted menu reads as unknown here,
    /// deliberately: it grants nothing, so accepting its code would store a grant that does nothing.</summary>
    public IReadOnlyList<string> UnknownMenus { get; init; } = [];

    public IReadOnlyList<string> UnknownPermissions { get; init; } = [];

    /// <summary>A granted child menu whose parent was not also granted. <b>Refused, not
    /// auto-completed</b> - silently widening a submitted grant is how an operator ends up having
    /// given away a menu they never ticked.</summary>
    public IReadOnlyList<string> MissingParentMenus { get; init; } = [];

    /// <summary>Permission points whose owning menu is not in the submitted menu set.</summary>
    public IReadOnlyList<string> PermissionsOutsideMenus { get; init; } = [];

    /// <summary>Service-level points (no owning menu) offered to a tenant-owned role. Only platform
    /// roles may hold them.</summary>
    public IReadOnlyList<string> NullMenuPermissions { get; init; } = [];

    /// <summary>
    /// Menus whose declared audience does not cover the role's tenant type.
    /// <para>
    /// <b>Never populated.</b> The audience rule was switched off across all three of its sites
    /// (this validator, the menu tree read and the handler's forced audience), because enforcing it
    /// on the write path alone would refuse exactly the configurations the read path still shows as
    /// legal. The field stays so that turning the rule back on needs no contract change.
    /// </para>
    /// </summary>
    public IReadOnlyList<string> AudienceViolations { get; init; } = [];

    /// <summary>Menus the caller does not hold themselves. A tenant caller can only pass on what
    /// they have - measured against their live authorization face, so a menu taken away from them is
    /// undelegatable on their very next request.</summary>
    public IReadOnlyList<string> MenusNotDelegable { get; init; } = [];

    public IReadOnlyList<string> PermissionsNotDelegable { get; init; } = [];

    /// <summary>Menus above the parent administrator role's ceiling.</summary>
    public IReadOnlyList<string> BeyondParentMenus { get; init; } = [];

    public IReadOnlyList<string> BeyondParentPermissions { get; init; } = [];

    /// <summary>True when no rule fired.</summary>
    public bool IsEmpty =>
        UnknownMenus.Count == 0
        && UnknownPermissions.Count == 0
        && MissingParentMenus.Count == 0
        && PermissionsOutsideMenus.Count == 0
        && NullMenuPermissions.Count == 0
        && AudienceViolations.Count == 0
        && MenusNotDelegable.Count == 0
        && PermissionsNotDelegable.Count == 0
        && BeyondParentMenus.Count == 0
        && BeyondParentPermissions.Count == 0;
}

/// <summary>Set an account's whole-dimension access, one dimension at a time.</summary>
public sealed record SetGlobalAccessRequest
{
    public GlobalAccessDimension Company { get; init; } = new();

    public GlobalAccessDimension Supplier { get; init; } = new();
}

/// <summary>One dimension of a whole-dimension grant.</summary>
public sealed record GlobalAccessDimension
{
    public bool ScopeAll { get; init; }

    /// <summary>Ignored when <see cref="ScopeAll"/> is false. Only platform roles are accepted: a
    /// tenant's own role granted across a whole dimension would take effect inside every other
    /// tenant of that dimension too.</summary>
    public IReadOnlyList<int> RoleIds { get; init; } = [];
}

/// <summary>Grant or revoke the platform super-administrator flag.</summary>
public sealed record SetSuperAdminRequest
{
    /// <summary>Nullable so an explicit <c>false</c> still counts as sent. A required non-nullable
    /// bool cannot tell "revoke" from "field missing".</summary>
    public bool? Enabled { get; init; }
}
