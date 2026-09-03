using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Platform;
using UserSvc.Infrastructure.Persistence.Tasks;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// <see cref="ITaskQueue"/> over <c>identity.task_queues</c> (db/0014_task_queues.sql).
/// <para>
/// The statements live in <see cref="TaskQueueSql"/>, with the reasoning for each; what is left
/// here is the argument checking, the batch marshalling and the projection onto the port's types.
/// Every statement goes through EF's own <c>FromSql</c> / <c>ExecuteSql</c> / <c>SqlQuery</c>
/// rather than a second data-access stack, which is what keeps them on this context's connection
/// and inside the caller's transaction (decision 15 - and the reason Directory.Packages.props
/// refuses Dapper).
/// </para>
/// <para>
/// <b>Neither of this context's two SaveChanges mechanisms applies to this table, deliberately.</b>
/// The outbox interceptor drains domain events off <c>Entity</c> subclasses and
/// <see cref="TaskQueueEntry"/> is not one - a queue row raises no events, it IS the notification.
/// The global soft-delete query filter belongs to <c>identity.users</c> and
/// <c>identity.user_identities</c>, and there is none here because a finished queue row is deleted
/// physically (argued in the script header). So the raw SQL below bypasses nothing: there is
/// nothing on this entity for it to bypass. Giving this entity a query filter or a domain event
/// later would break that, and <see cref="PopAsync"/> in particular would have to be re-examined.
/// </para>
/// <para>
/// <b>Registered scoped</b>, like every other repository here, so a producer's business write and
/// its enqueue share one context and therefore one transaction.
/// </para>
/// </summary>
public sealed class TaskQueueRepository(UserSvcDbContext db) : ITaskQueue
{
    /// <summary>An empty JSON object - what an unspecified payload is stored as.</summary>
    private const string EmptyPayload = "{}";

    /// <inheritdoc />
    public async Task<int> PushIfNotExistsAsync(
        IReadOnlyCollection<TaskEnqueueRequest> tasks, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tasks);

        // Nothing to enqueue is a no-op and not an error: a producer that reconciles a set is
        // entitled to find the set empty. Checked before the statement so an empty batch costs no
        // round trip.
        if (tasks.Count == 0)
        {
            return 0;
        }

        var items = tasks.ToArray();
        var queueNames = new string[items.Length];
        var taskIds = new string[items.Length];
        var priorities = new int[items.Length];
        var payloads = new string[items.Length];
        var delays = new TimeSpan?[items.Length];
        var actors = new string[items.Length];

        for (var i = 0; i < items.Length; i++)
        {
            var item = items[i];

            // Refused here rather than by the database. A blank queue name satisfies every
            // constraint on the table and is then polled by nobody, which is a task that silently
            // never runs; a negative priority would come back as SQLSTATE 23514 naming
            // chk_task_queues_priority - true, but two layers away from the caller that made the
            // mistake. The CHECK stays as the data-level backstop for a hand-written INSERT.
            ArgumentException.ThrowIfNullOrWhiteSpace(item.QueueName);
            ArgumentException.ThrowIfNullOrWhiteSpace(item.TaskId);
            ArgumentOutOfRangeException.ThrowIfNegative(item.Priority);

            queueNames[i] = item.QueueName;
            taskIds[i] = item.TaskId;
            priorities[i] = item.Priority;

            // A missing payload becomes {} rather than reaching the database as '' and failing the
            // ::jsonb cast with SQLSTATE 22P02. Anything non-blank is passed through unchanged and
            // must be valid JSON - a producer sending malformed JSON has a bug the database should
            // report, not one this adapter should paper over.
            payloads[i] = string.IsNullOrWhiteSpace(item.PayloadJson) ? EmptyPayload : item.PayloadJson;

            delays[i] = item.Delay;
            actors[i] = item.Actor;
        }

        return await db.Database.ExecuteSqlAsync(
            TaskQueueSql.Push(queueNames, taskIds, priorities, payloads, delays, actors),
            cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<QueuedTask>> PopAsync(
        string queueName, int limit, string poppedBy, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(queueName);

        // A batch of zero or less is a no-op and not an error: the runner computes its batch size
        // as "free worker slots", and having none is the normal state of a busy pool. Checked
        // before the statement because LIMIT 0 would still take a round trip - and LIMIT -1 is a
        // syntax error.
        if (limit <= 0)
        {
            return [];
        }

        // Nothing may be composed here beyond what ClaimQuery already carries - see its remarks.
        var rows = await ClaimQuery(db, queueName, limit, poppedBy).ToListAsync(cancellationToken);

        // Claim order is restored here rather than asked of the UPDATE. An UPDATE ... RETURNING
        // makes no promise about the order it emits rows in - it is the order the outer join
        // happened to produce - so a worker pool smaller than the batch would otherwise start work
        // in an order nobody chose, and the priority column would quietly stop meaning anything.
        return
        [
            .. rows
                .OrderByDescending(row => row.Priority)
                .ThenBy(row => row.DeliverOn)
                .ThenBy(row => row.Id)
                .Select(Project),
        ];
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(int id, CancellationToken cancellationToken)
    {
        // ExecuteDelete rather than raw SQL: there is no clause here EF cannot write, and it runs
        // on the same connection and in the same transaction as everything else. It also skips the
        // change tracker, which is what we want - loading the row in order to delete it would be a
        // second round trip and a lost-update window for no gain.
        var affected = await db.TaskQueues
            .Where(entry => entry.Id == id)
            .ExecuteDeleteAsync(cancellationToken);

        // False means "already gone", which is what a duplicate delivery of a finished task looks
        // like, and is why the caller gets a bool instead of an exception.
        return affected > 0;
    }

    /// <inheritdoc />
    public async Task<bool> ReArmAsync(
        int id, TimeSpan delay, string actor, CancellationToken cancellationToken)
    {
        var affected = await db.Database.ExecuteSqlAsync(
            TaskQueueSql.ReArm(id, delay, actor), cancellationToken);

        return affected > 0;
    }

    /// <inheritdoc />
    public async Task<int> RecoverStaleAsync(
        TimeSpan timeout, string actor, CancellationToken cancellationToken)
    {
        // Zero or less is the off switch, and it is checked here rather than folded into the
        // statement on purpose: a timeout of zero in the WHERE clause would reclaim every row the
        // instant it was claimed, which is the worst available reading of "the reclaim is
        // disabled" - it would take work away from the workers currently doing it.
        if (timeout <= TimeSpan.Zero)
        {
            return 0;
        }

        return await db.Database.ExecuteSqlAsync(
            TaskQueueSql.RecoverStale(timeout, actor), cancellationToken);
    }

    /// <inheritdoc />
    public Task<int> CountPendingAsync(string queueName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(queueName);

        return db.Database
            .SqlQuery<int>(TaskQueueSql.CountPending(queueName))
            .SingleAsync(cancellationToken);
    }

    /// <summary>
    /// The query <see cref="PopAsync"/> runs, verbatim, exposed so that the one property it must
    /// have can be asserted without a database - the same reason <see cref="BackendUserSql"/> is
    /// public.
    /// <para>
    /// <b><c>AsNoTracking</c> is the only operator that may appear on it, and nothing may be
    /// composed onto the result.</b> PostgreSQL allows a data-modifying <c>WITH</c> only at the
    /// top level of a statement, and EF wraps a <c>FromSql</c> in <c>SELECT ... FROM (...)</c> the
    /// moment anything translatable is composed onto it. Measured both ways: <c>AsNoTracking</c>
    /// changes the emitted SQL not at all, while adding an <c>OrderBy</c> here fails ten of the
    /// fourteen integration tests with "WITH clause containing a data-modifying statement must be
    /// at the top level".
    /// </para>
    /// <para>
    /// It is no-tracking because these rows are read once and never written through the change
    /// tracker: a tracked copy would invite a caller to mutate one and SaveChanges over a row whose
    /// only legitimate writers are the statements in <see cref="TaskQueueSql"/>.
    /// </para>
    /// </summary>
    /// <param name="db">The context to run on.</param>
    /// <param name="queueName">The queue to claim from.</param>
    /// <param name="limit">The most rows to claim.</param>
    /// <param name="poppedBy">The claiming runner's identifier.</param>
    /// <returns>The unexecuted claim query.</returns>
    public static IQueryable<TaskQueueEntry> ClaimQuery(
        UserSvcDbContext db, string queueName, int limit, string poppedBy)
    {
        ArgumentNullException.ThrowIfNull(db);

        return db.TaskQueues
            .FromSql(TaskQueueSql.Pop(queueName, limit, poppedBy))
            .AsNoTracking();
    }

    /// <summary>
    /// The persistence row as the port describes it. <c>popped</c> is dropped because a row that
    /// reached here is claimed by construction, and the audit columns are dropped because they are
    /// for an operator reading the table rather than input for a handler.
    /// </summary>
    private static QueuedTask Project(TaskQueueEntry row) => new(
        row.Id,
        row.QueueName,
        row.TaskId,
        row.Priority,
        row.PayloadJson,
        row.DeliverOn,
        row.CreatedAt,
        row.PoppedAt,
        row.PoppedBy);
}
