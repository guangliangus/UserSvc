namespace BuildingBlocks.Core.Domain;

/// <summary>Base entity with a surrogate auto-increment primary key (team rule: no business keys as PK).</summary>
public abstract class Entity
{
    public int Id { get; protected set; }
}
