using Microsoft.EntityFrameworkCore;
using Npgsql;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Infrastructure.Persistence;

/// <summary>
/// The transaction boundary, plus the one place EF's write failures are translated into the
/// application's error vocabulary.
/// <para>
/// Domain events are drained into the outbox by
/// <see cref="DomainEventOutboxInterceptor"/> rather than here, so that saves issued by libraries
/// sharing this context are covered too.
/// </para>
/// </summary>
public sealed class UnitOfWork(UserSvcDbContext db) : IUnitOfWork
{
    /// <summary>PostgreSQL unique_violation.</summary>
    private const string UniqueViolation = "23505";

    public async Task<int> SaveChangesAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // xmin said another writer got there first. The caller must re-read and retry, which
            // is what 409 tells them - without this the promise made by UseXminConcurrencyToken
            // would surface as an opaque 500.
            throw new ConflictException(
                ErrorCodes.ConcurrencyConflict,
                "The record was modified by someone else. Re-read it and try again.",
                ex);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: UniqueViolation } pg)
        {
            throw new ConflictException(
                ErrorCodes.Conflict,
                $"The value violates the uniqueness constraint '{pg.ConstraintName}'.",
                ex);
        }
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
}
