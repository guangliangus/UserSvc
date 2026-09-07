namespace BuildingBlocks.Core.Domain;

/// <summary>Audit columns filled automatically by the EF Core save interceptor.</summary>
public interface IAuditable
{
    DateTimeOffset CreatedAt { get; set; }
    string CreatedBy { get; set; }
    DateTimeOffset UpdatedAt { get; set; }
    string UpdatedBy { get; set; }
}
