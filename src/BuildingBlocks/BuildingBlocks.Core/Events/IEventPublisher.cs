namespace BuildingBlocks.Core.Events;

/// <summary>
/// Publishes integration events. The default API-side implementation is the transactional
/// outbox (rows committed with the business change, delivered by a background dispatcher);
/// hosts without a DbContext use the direct RabbitMQ publisher.
/// </summary>
public interface IEventPublisher
{
    Task PublishAsync<TEvent>(TEvent @event, CancellationToken cancellationToken = default)
        where TEvent : IntegrationEvent;
}
