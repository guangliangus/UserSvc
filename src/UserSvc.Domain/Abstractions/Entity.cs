namespace UserSvc.Domain.Abstractions;

/// <summary>
/// Base class for entities that raise domain events. Events accumulate on the aggregate and the
/// unit of work writes them to the outbox as part of the same transaction (decision 16: the
/// business row and the event row are committed atomically or not at all).
/// </summary>
public abstract class Entity
{
    private readonly List<IDomainEvent> _domainEvents = [];

    public IReadOnlyList<IDomainEvent> DomainEvents => _domainEvents;

    protected void Raise(IDomainEvent domainEvent) => _domainEvents.Add(domainEvent);

    public void ClearDomainEvents() => _domainEvents.Clear();
}
