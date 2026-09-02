namespace UserSvc.Application.Features.BackOffice.Rbac.Contracts;

/// <summary>Create a role.</summary>
public sealed record CreateRoleRequest
{
    /// <summary>Stable handle, immutable once created.</summary>
    public string Code { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    /// <summary>platform / supplier / company. Validated in the service rather than by the model
    /// binder, so a wrong value answers <c>ROLE_CATEGORY_INVALID</c> instead of a generic binding
    /// failure. Immutable after creation.</summary>
    public string Category { get; init; } = string.Empty;

    public string Description { get; init; } = string.Empty;

    /// <summary>Omit to mean "my only owner candidate". Sending one you do not administer is
    /// refused rather than silently corrected.</summary>
    public string? OwnerType { get; init; }

    public string? OwnerCode { get; init; }

    /// <summary>Null = top level. Must be an administrator role the caller holds, unless the caller
    /// is the platform super administrator.</summary>
    public int? ParentRoleId { get; init; }

    /// <summary>Only the platform super administrator can set this, and only on a platform role.</summary>
    public bool IsAdmin { get; init; }

    /// <summary>Optional initial grants, validated by the same cascade the grant editor uses.</summary>
    public IReadOnlyList<string> MenuCodes { get; init; } = [];

    public IReadOnlyList<string> PermissionCodes { get; init; } = [];
}

/// <summary>
/// Edit a role. <b>Category is deliberately absent</b> - it is immutable, and offering a field the
/// server ignores is worse than not offering it.
/// <para>
/// PUT means full replacement: the client always sends the current value of
/// <see cref="ParentRoleId"/>, and null means "move to top level", not "leave alone".
/// </para>
/// </summary>
public sealed record UpdateRoleRequest
{
    public string Name { get; init; } = string.Empty;

    public string Description { get; init; } = string.Empty;

    public int? ParentRoleId { get; init; }
}

/// <summary>A role as the back office renders it.</summary>
public sealed record RoleResponse
{
    public int Id { get; init; }

    public string Code { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    /// <summary>Empty for a legacy row that was never re-filed; such a role is bindable nowhere.</summary>
    public string Category { get; init; } = string.Empty;

    public string Description { get; init; } = string.Empty;

    public string OwnerType { get; init; } = string.Empty;

    /// <summary>Null for a platform role - it has no owner.</summary>
    public string? OwnerCode { get; init; }

    public bool IsAdmin { get; init; }

    public int? ParentRoleId { get; init; }

    /// <summary>Purely for display, and resolved against the <b>full</b> catalogue: a child's group
    /// leader may itself be hidden from this caller, and without the code the role page would render
    /// an ungrouped orphan.</summary>
    public string? ParentRoleCode { get; init; }

    /// <summary>The caller may see this role but not edit it. Computed from the same narrowed scope
    /// the write path uses, so the UI only offers edits the server will accept.</summary>
    public bool Readonly { get; init; }

    /// <summary>Union of the two dimension flags, kept for compatibility. <b>Role assignment must
    /// filter on the per-dimension flags</b> - the union offers a company role inside a supplier
    /// tenant, which the write path then refuses.</summary>
    public bool Bindable { get; init; }

    public bool BindableCompany { get; init; }

    public bool BindableSupplier { get; init; }

    public DateTimeOffset? CreatedAt { get; init; }

    public DateTimeOffset? UpdatedAt { get; init; }
}

/// <summary>Answer of the create/edit form's duplicate-name probe.</summary>
public sealed record RoleNameExistsResponse
{
    public bool Exists { get; init; }
}

/// <summary>
/// What the caller may do with roles, so the UI can ask before it offers. Open to every
/// authenticated back-office user - it only describes the caller's own standing.
/// </summary>
public sealed record MyRoleScopeResponse
{
    public bool IsSuperAdmin { get; init; }

    /// <summary>False is a normal answer here, not an error: failing the gate simply means the role
    /// page is read-only.</summary>
    public bool CanManageRoles { get; init; }

    /// <summary>The owners the caller may create or edit roles for. Every entry is one the write
    /// path will actually accept.</summary>
    public IReadOnlyList<RoleScopeOwnerResponse> Owners { get; init; } = [];

    public IReadOnlyList<RoleScopeAdminRoleResponse> AdminRoles { get; init; } = [];
}

/// <summary>One owner the caller may write roles for, and the administrator roles that grant it.</summary>
public sealed record RoleScopeOwnerResponse
{
    public string OwnerType { get; init; } = string.Empty;

    /// <summary>Null, and still present, for a platform owner.</summary>
    public string? OwnerCode { get; init; }

    /// <summary>
    /// Candidate parent roles for a role created under this owner.
    /// <para>
    /// The UI needs them per owner because an administrator role is by construction platform-owned,
    /// so <see cref="RoleScopeAdminRoleResponse.OwnerType"/> always describes the <i>role</i>, never
    /// the tenant the caller holds it through - filtering the flat list by the selected owner would
    /// always come back empty.
    /// </para>
    /// </summary>
    public IReadOnlyList<int> AdminRoleIds { get; init; } = [];
}

/// <summary>An administrator role the caller holds, wherever they hold it.</summary>
public sealed record RoleScopeAdminRoleResponse
{
    public int Id { get; init; }

    public string Code { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    public string OwnerType { get; init; } = string.Empty;

    public string? OwnerCode { get; init; }
}

/// <summary>A role reduced to what a member list needs to render it.</summary>
public sealed record RoleBriefResponse
{
    public int Id { get; init; }

    public string Code { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;
}

/// <summary>One dimension of an account's data-scope envelope.</summary>
public sealed record RoleScopeResponse
{
    public string ScopeType { get; init; } = string.Empty;

    /// <summary>Always an array. Empty alongside <see cref="IsGlobal"/> means "everything", not
    /// "nothing".</summary>
    public IReadOnlyList<string> Values { get; init; } = [];

    public bool IsGlobal { get; init; }
}
