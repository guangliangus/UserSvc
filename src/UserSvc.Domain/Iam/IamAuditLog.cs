namespace UserSvc.Domain.Iam;

/// <summary>
/// One IAM administrative action, as it happened. <b>Append-only</b>: there is no update path and
/// no delete path anywhere in this service, and the repository port exposes nothing but an append -
/// a log a caller can rewrite answers a different question from the one it was built to answer.
/// <para>
/// Writing one is always best effort. An audit insert failing must not fail the request that
/// succeeded; the alternative rolls back a completed role change because a log row would not go in.
/// </para>
/// </summary>
public sealed class IamAuditLog
{
    public int Id { get; set; }

    /// <summary>The back-office account that performed the action. Not a foreign key: the actor
    /// lives in another bounded context, and an audit row must outlive the account it names.</summary>
    public int ActorUserId { get; set; }

    public string? ActorName { get; set; }

    /// <summary>The tenant the action was taken in, or <c>platform</c> when the caller was acting
    /// as the platform.</summary>
    public string? TenantType { get; set; }

    public string? TenantCode { get; set; }

    public string Action { get; set; } = string.Empty;

    public string? TargetType { get; set; }

    /// <summary>Text, not an integer: the target of an IAM action is a role id today and could be a
    /// tenant code tomorrow.</summary>
    public string? TargetId { get; set; }

    /// <summary><b>jsonb</b>, raw text. Null when there was no prior state (a create).</summary>
    public string? BeforeData { get; set; }

    /// <summary><b>jsonb</b>, raw text. Null when there is no resulting state (a delete).</summary>
    public string? AfterData { get; set; }

    public string? Ip { get; set; }

    public string? RequestId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>Action names written to <see cref="IamAuditLog.Action"/>.</summary>
public static class IamAuditActions
{
    public const string RoleCreate = "ROLE_CREATE";
    public const string RoleUpdate = "ROLE_UPDATE";
    public const string RoleDelete = "ROLE_DELETE";
    public const string RoleGrantsUpdate = "ROLE_GRANTS_UPDATE";
    public const string MenuDelete = "MENU_DELETE";

    /// <summary>Whole-dimension (global) access changes. The name is deliberately about the member
    /// rows the endpoint actually rewrites, not about the endpoint: slice 12's audit reader queries
    /// this table by action, so the string is a shared contract and not ours to improve on.</summary>
    public const string MemberRolesUpdate = "MEMBER_ROLES_UPDATE";
    public const string SuperAdminGrant = "SUPER_ADMIN_GRANT";
    public const string SuperAdminRevoke = "SUPER_ADMIN_REVOKE";
}

/// <summary>Values written to <see cref="IamAuditLog.TargetType"/>.</summary>
public static class IamAuditTargetTypes
{
    public const string Role = "role";
    public const string Menu = "menu";
    public const string User = "user";

    /// <summary>A tenant membership row. Whole-dimension access is recorded against this rather than
    /// against the account, because a membership is what the write touches.</summary>
    public const string Member = "member";
}

/// <summary>The tenant type stamped on an action taken by the platform rather than inside a
/// tenant.</summary>
public static class IamAuditTenantTypes
{
    public const string Platform = "platform";
}
