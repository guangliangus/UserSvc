namespace UserSvc.Application.Features.BackOffice.Tenants;

/// <summary>A role as the roster renders it. Ids are numbers on the wire (decision 09).</summary>
public sealed record TenantRoleResponse
{
    public required int Id { get; init; }

    public string Code { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;
}

/// <summary>One row of the tenant roster.</summary>
public sealed record TenantMemberResponse
{
    public required int UserId { get; init; }

    /// <summary>The single display name rule for back-office accounts: both name parts when they
    /// are there, the nickname otherwise. The roster, the audit trail and the shell header all
    /// read it, so that one person is not called two different things in two places.</summary>
    public string Nickname { get; init; } = string.Empty;

    public string Email { get; init; } = string.Empty;

    public string StaffCode { get; init; } = string.Empty;

    public string DeptName { get; init; } = string.Empty;

    public bool IsAdmin { get; init; }

    /// <summary>Never null. An empty list means "no roles yet", which is a normal state for a
    /// member who has been added but not configured.</summary>
    public IReadOnlyList<TenantRoleResponse> Roles { get; init; } = [];

    public string Status { get; init; } = string.Empty;
}

/// <summary>A page of the roster.</summary>
public sealed record TenantMemberListResponse
{
    public IReadOnlyList<TenantMemberResponse> Items { get; init; } = [];

    public required int Total { get; init; }

    public required int Page { get; init; }

    public required int PageSize { get; init; }
}

/// <summary>The account details for somebody who has no back-office account yet.</summary>
public sealed record NewMemberAccountRequest
{
    public string Email { get; init; } = string.Empty;

    public string Nickname { get; init; } = string.Empty;

    public string FirstName { get; init; } = string.Empty;

    public string LastName { get; init; } = string.Empty;
}

/// <summary>
/// Add a member, or revive one who was removed.
/// <para>
/// Exactly one of <see cref="UserId"/> and <see cref="NewUser"/> carries the target. Both, or
/// neither, is refused rather than guessed at - guessing here means either adding the wrong person
/// or opening a second account for somebody who already has one.
/// </para>
/// </summary>
public sealed record CreateMemberRequest
{
    /// <summary>An existing back-office account. Zero when inviting somebody new.</summary>
    public int UserId { get; init; }

    public NewMemberAccountRequest? NewUser { get; init; }

    /// <summary>May be empty: a member with no roles sees the dashboard and nothing else, which is
    /// a legitimate first step.</summary>
    public IReadOnlyList<int> RoleIds { get; init; } = [];

    public string DeptName { get; init; } = string.Empty;
}

/// <summary>
/// The outcome of adding a member.
/// <para>
/// <see cref="ReusedAccount"/> and <see cref="EmailSent"/> have to be read together:
/// <c>false</c>/<c>false</c> - a brand new account whose password could not be sent - is the one
/// combination that needs an administrator to do something, and it is why the send result is
/// reported instead of thrown.
/// </para>
/// <para>
/// There is deliberately no initial-password field. The password of a newly created account
/// travels by e-mail only; a field that is contractually always empty is worse than no field,
/// because the next reader will try to use it.
/// </para>
/// </summary>
public sealed record CreateMemberResponse
{
    public required int MemberId { get; init; }

    public required int UserId { get; init; }

    public required bool ReusedAccount { get; init; }

    public required bool EmailSent { get; init; }
}

/// <summary>Replace a member's roles. The set is authoritative, except for bindings the caller is
/// not entitled to touch - those are merged back in by the service.</summary>
public sealed record UpdateMemberRolesRequest
{
    public IReadOnlyList<int> RoleIds { get; init; } = [];
}

/// <summary>Suspend or reinstate a membership. REMOVED is not accepted here - removal has its own
/// verb, and its own audit action.</summary>
public sealed record UpdateMemberStatusRequest
{
    public string Status { get; init; } = string.Empty;
}

/// <summary>The outcome of resetting a member's password. The password itself is never in here.</summary>
public sealed record ResetMemberPasswordResponse
{
    public required int UserId { get; init; }

    public required bool EmailSent { get; init; }
}
