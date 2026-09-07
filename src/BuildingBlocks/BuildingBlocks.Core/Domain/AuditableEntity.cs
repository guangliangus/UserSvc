namespace BuildingBlocks.Core.Domain;

/// <summary>Convenience base for the common case: int PK + audit columns + soft delete.</summary>
public abstract class AuditableEntity : Entity, IAuditable, ISoftDeletable
{
    public DateTimeOffset CreatedAt { get; set; }
    public string CreatedBy { get; set; } = SystemActorName;
    public DateTimeOffset UpdatedAt { get; set; }
    public string UpdatedBy { get; set; } = SystemActorName;
    public string Status { get; set; } = EntityStatus.Active;

    private const string SystemActorName = "system";
}
