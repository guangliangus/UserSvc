using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Abstractions;
using UserSvc.Infrastructure.Persistence.Outbox;

namespace UserSvc.Infrastructure.Persistence;

/// <summary>
/// The transaction boundary. <b>The point of interest is the first line of
/// <see cref="SaveChangesAsync"/></b>: domain events become outbox rows inside the same
/// SaveChanges, so the business row and the event row either both exist or neither does
/// (decision 16).
/// </summary>
public sealed class UnitOfWork(UserSvcDbContext db) : IUnitOfWork
{
    private static readonly JsonSerializerOptions PayloadOptions = new(JsonSerializerDefaults.Web);

    public async Task<int> SaveChangesAsync(CancellationToken cancellationToken)
    {
        DrainDomainEventsIntoOutbox();
        return await db.SaveChangesAsync(cancellationToken);
    }

    public async Task ExecuteInTransactionAsync(
        Func<CancellationToken, Task> action,
        CancellationToken cancellationToken)
    {
        // The execution strategy retries PostgreSQL transient failures. It requires the whole
        // transaction to be replayable, so the transaction must be opened inside the strategy.
        var strategy = db.Database.CreateExecutionStrategy();
        await strategy.ExecuteAsync(async ct =>
        {
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            await action(ct);
            await transaction.CommitAsync(ct);
        }, cancellationToken);
    }

    private void DrainDomainEventsIntoOutbox()
    {
        var entities = db.ChangeTracker
            .Entries<Entity>()
            .Where(e => e.Entity.DomainEvents.Count > 0)
            .Select(e => e.Entity)
            .ToList();

        if (entities.Count == 0)
        {
            return;
        }

        var traceParent = Activity.Current?.Id ?? string.Empty;

        foreach (var entity in entities)
        {
            foreach (var domainEvent in entity.DomainEvents)
            {
                db.OutboxMessages.Add(new OutboxMessage
                {
                    MessageId = Guid.CreateVersion7().ToString("n"),
                    EventName = ResolveEventName(domainEvent),
                    Payload = JsonSerializer.Serialize(domainEvent, domainEvent.GetType(), PayloadOptions),
                    TraceParent = traceParent,
                    OccurredAt = domainEvent.OccurredAt,
                });
            }

            entity.ClearDomainEvents();
        }
    }

    private static string ResolveEventName(IDomainEvent domainEvent)
    {
        var type = domainEvent.GetType();
        var attribute = (EventNameAttribute?)Attribute.GetCustomAttribute(type, typeof(EventNameAttribute));

        return attribute?.Name
               ?? throw new InvalidOperationException(
                   $"{type.Name} must carry [EventName] — the wire name is a contract and cannot be derived from the class name.");
    }
}
