namespace UserSvc.Domain.Abstractions;

/// <summary>A fact that happened inside the domain and is worth telling the outside world about.
/// The infrastructure layer turns these into integration events.</summary>
public interface IDomainEvent
{
    DateTimeOffset OccurredAt { get; }
}
