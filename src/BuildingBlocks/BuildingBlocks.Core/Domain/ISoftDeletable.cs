namespace BuildingBlocks.Core.Domain;

/// <summary>
/// Soft delete via a status column (team rule: no physical deletes).
/// EF Core deletes are converted to <see cref="EntityStatus.Deleted"/> updates and a
/// global query filter hides deleted rows.
/// </summary>
public interface ISoftDeletable
{
    /// <summary>ACTIVE | DELETED</summary>
    string Status { get; set; }
}

public static class EntityStatus
{
    public const string Active = "ACTIVE";
    public const string Deleted = "DELETED";
}
