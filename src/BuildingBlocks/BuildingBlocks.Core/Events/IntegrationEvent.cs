namespace BuildingBlocks.Core.Events;

/// <summary>
/// Base contract for events crossing service boundaries. <see cref="MessageId"/> drives
/// consumer-side idempotency (inbox); <see cref="OccurredAt"/> is business time, not publish time.
/// </summary>
public abstract record IntegrationEvent
{
    public Guid MessageId { get; init; } = Guid.NewGuid();
    public DateTimeOffset OccurredAt { get; init; } = DateTimeOffset.UtcNow;
}
