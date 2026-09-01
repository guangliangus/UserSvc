namespace UserSvc.Application.Ports.Platform;

/// <summary>
/// The transaction boundary. Repositories resolved in the same scope share one persistence
/// context and therefore one transaction — which is what makes the business row and the outbox
/// row commit atomically (decision 16).
/// </summary>
public interface IUnitOfWork
{
    Task<int> SaveChangesAsync(CancellationToken cancellationToken);

    /// <summary>An explicit transaction spanning several SaveChanges calls, wrapped in the
    /// PostgreSQL transient-failure retry strategy.</summary>
    Task ExecuteInTransactionAsync(Func<CancellationToken, Task> action, CancellationToken cancellationToken);
}
