namespace UserSvc.Domain.Iam;

/// <summary>
/// One menu granted to one role. Two invariants ride on this table and are enforced by the
/// application layer, not by the database: every granted permission point's owning menu must be
/// granted here, and granting a child implies granting its parent.
/// </summary>
public sealed class RoleMenu
{
    public int Id { get; set; }

    public int RoleId { get; set; }

    public int MenuId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public string? CreatedBy { get; set; }
}
