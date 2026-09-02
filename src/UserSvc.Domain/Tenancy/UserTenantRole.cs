namespace UserSvc.Domain.Tenancy;

/// <summary>
/// A role bound to a tenant membership.
/// <para>
/// Keyed by <see cref="MemberId"/> and <b>not</b> by user id, which is the whole point: the same
/// person can hold "finance" in one company and nothing at all in the next, and a user-keyed
/// binding table could not express that.
/// </para>
/// </summary>
public sealed class UserTenantRole
{
    public int Id { get; set; }

    /// <summary><c>iam.tenant_members.id</c>.</summary>
    public int MemberId { get; set; }

    /// <summary><c>iam.roles.id</c>. Same bounded context, so a real foreign key - unlike the
    /// reference to the C-end <c>identity</c> schema, which stays logical.</summary>
    public int RoleId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public string? CreatedBy { get; set; }
}
