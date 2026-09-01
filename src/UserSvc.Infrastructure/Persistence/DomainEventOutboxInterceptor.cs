using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using UserSvc.Domain.Abstractions;
using UserSvc.Infrastructure.Persistence.Outbox;

namespace UserSvc.Infrastructure.Persistence;

/// <summary>
/// Turns accumulated domain events into outbox rows immediately before the context saves
/// (decision 16). The business row and the event row therefore land in the same transaction.
/// <para>
/// This lives in an interceptor rather than in <see cref="UnitOfWork"/> on purpose. Libraries that
/// share this DbContext - OpenIddict's EF stores among them - call
/// <see cref="DbContext.SaveChangesAsync(CancellationToken)"/> directly and never pass through
/// <see cref="UnitOfWork"/>. Draining there would silently skip the outbox on exactly those saves
/// and leave the events stranded on the entities, which is a decision-16 violation that produces
/// no error at all.
/// </para>
/// </summary>
public sealed class DomainEventOutboxInterceptor : SaveChangesInterceptor
{
    private static readonly JsonSerializerOptions PayloadOptions = new(JsonSerializerDefaults.Web);

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        if (eventData.Context is not null)
        {
            Drain(eventData.Context);
        }

        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    public override InterceptionResult<int> SavingChanges(
        DbContextEventData eventData,
        InterceptionResult<int> result)
    {
        if (eventData.Context is not null)
        {
            Drain(eventData.Context);
        }

        return base.SavingChanges(eventData, result);
    }

    private static void Drain(DbContext context)
    {
        var carriers = context.ChangeTracker
            .Entries<Entity>()
            .Where(e => e.Entity.DomainEvents.Count > 0)
            .Select(e => e.Entity)
            .ToList();

        if (carriers.Count == 0)
        {
            return;
        }

        var traceParent = Activity.Current?.Id ?? string.Empty;

        foreach (var carrier in carriers)
        {
            foreach (var domainEvent in carrier.DomainEvents)
            {
                context.Set<OutboxMessage>().Add(new OutboxMessage
                {
                    MessageId = Guid.CreateVersion7().ToString("n"),
                    EventName = ResolveEventName(domainEvent),
                    Payload = JsonSerializer.Serialize(domainEvent, domainEvent.GetType(), PayloadOptions),
                    TraceParent = traceParent,
                    OccurredAt = domainEvent.OccurredAt,
                });
            }

            carrier.ClearDomainEvents();
        }
    }

    private static string ResolveEventName(IDomainEvent domainEvent)
    {
        var type = domainEvent.GetType();
        var attribute = (EventNameAttribute?)Attribute.GetCustomAttribute(type, typeof(EventNameAttribute));

        return attribute?.Name
               ?? throw new InvalidOperationException(
                   $"{type.Name} must carry [EventName] - the wire name is a contract and cannot be derived from the class name.");
    }
}
