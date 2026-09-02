namespace UserSvc.Domain.Iam;

/// <summary>One permission point granted to one role. Replaced wholesale rather than edited: the
/// grant writer deletes the role's rows and inserts the new set inside one transaction.</summary>
public sealed class RolePermission
{
    public int Id { get; set; }

    public int RoleId { get; set; }

    public int PermissionId { get; set; }

    public DateTimeOffset? CreatedAt { get; set; }

    public string? CreatedBy { get; set; }
}
