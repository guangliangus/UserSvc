using System.Collections.Concurrent;
using System.Globalization;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>
/// One delivery of one task to a handler, as the journal saw it.
/// <para>
/// <see cref="Attempt"/> is what makes at-least-once delivery visible: a task id that appears with
/// attempt 2 was handed to a worker twice, whether because its handler re-armed it, because the
/// reclaim released a claim, or - the failure these tests exist to catch - because two runners
/// claimed the same row.
/// </para>
/// </summary>
/// <param name="RowId">The queue row's surrogate key.</param>
/// <param name="TaskId">The producer's idempotency key.</param>
/// <param name="QueueName">The queue it was claimed from.</param>
/// <param name="Priority">The row's priority.</param>
/// <param name="PoppedBy">The runner instance that claimed it, straight off the row.</param>
/// <param name="Attempt">How many times this task id had been delivered, counting this one.</param>
/// <param name="At">When the handler was entered, on this process's clock. Only ever compared with
/// another value from the same clock.</param>
internal sealed record TaskDelivery(
    int RowId,
    string TaskId,
    string QueueName,
    int Priority,
    string PoppedBy,
    int Attempt,
    DateTimeOffset At);

/// <summary>
/// Everything a handler is given, handed to a test's own behaviour delegate.
/// <para>
/// <see cref="Queue"/> and <see cref="UnitOfWork"/> come from the task's own scope, which is the
/// point: a handler owns its queue row and may open its own transaction, and a test behaviour has
/// to be able to do both exactly as a real handler would.
/// </para>
/// </summary>
/// <param name="Task">The claimed task.</param>
/// <param name="Queue">The queue port, scoped to this task.</param>
/// <param name="UnitOfWork">The unit of work, scoped to this task.</param>
/// <param name="Attempt">How many times this task id has now been delivered, counting this one.</param>
/// <param name="CancellationToken">The task's own deadline - never the host's shutdown token.</param>
internal sealed record TaskHandlerContext(
    QueuedTask Task,
    ITaskQueue Queue,
    IUnitOfWork UnitOfWork,
    int Attempt,
    CancellationToken CancellationToken);

/// <summary>
/// The shared record of what the runners actually did, and the seam a test uses to decide how a
/// handler behaves.
/// <para>
/// It is a singleton in each worker host and <b>the same instance can be given to several
/// hosts</b>, which is what makes the concurrency test possible: four independent runner loops in
/// four independent hosts, one journal, so "no row was handed to two workers" is a question about
/// one list rather than a comparison of four.
/// </para>
/// <para>
/// The behaviour is a delegate rather than a set of flags because the interesting handler
/// behaviours are not a fixed menu - delete, re-arm with a real backoff, throw once and then
/// succeed, hold the task open while shutdown begins, ignore or honour the deadline - and each test
/// wants to close over its own state (a countdown, a <see cref="TaskCompletionSource"/>, a
/// recorded token state) while it does it.
/// </para>
/// </summary>
internal sealed class TaskJournal
{
    private readonly ConcurrentQueue<TaskDelivery> _deliveries = new();
    private readonly ConcurrentDictionary<string, int> _attempts = new(StringComparer.Ordinal);
    private readonly Func<TaskHandlerContext, Task> _behaviour;
    private int _completed;
    private int _running;

    /// <param name="behaviour">What the handler does with each task. The default is what a
    /// well-behaved handler does with work it finished: delete the row, terminally.</param>
    public TaskJournal(Func<TaskHandlerContext, Task>? behaviour = null) =>
        _behaviour = behaviour ?? (context => context.Queue.DeleteAsync(
            context.Task.Id, context.CancellationToken));

    /// <summary>Every delivery, in the order handlers were entered.</summary>
    public IReadOnlyList<TaskDelivery> Deliveries => [.. _deliveries];

    /// <summary>How many handler invocations returned without throwing.</summary>
    public int Completed => Volatile.Read(ref _completed);

    /// <summary>How many handler invocations are inside the behaviour right now.</summary>
    public int Running => Volatile.Read(ref _running);

    /// <summary>The distinct task ids that were delivered, sorted, for set assertions.</summary>
    public IReadOnlyList<string> DistinctTaskIds =>
        [.. _deliveries.Select(delivery => delivery.TaskId).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];

    /// <summary>The task ids in delivery order, for the ordering assertions.</summary>
    public IReadOnlyList<string> TaskIdsInOrder => [.. _deliveries.Select(delivery => delivery.TaskId)];

    /// <summary>
    /// Waits until at least <paramref name="count"/> deliveries have been recorded.
    /// <para>
    /// Polling rather than a signal, because what is being waited for is a real runner on a real
    /// poll interval against a real database: the test cannot know how many polls it will take, and
    /// a fixed sleep would either be flaky or be slower than every machine it ever runs on.
    /// </para>
    /// </summary>
    /// <param name="count">How many deliveries to wait for.</param>
    /// <param name="timeout">How long to wait before giving up.</param>
    /// <returns>True when they arrived, false on timeout.</returns>
    public Task<bool> WaitForDeliveriesAsync(int count, TimeSpan timeout) =>
        Poll.UntilAsync(() => _deliveries.Count >= count, timeout);

    /// <summary>Waits until at least <paramref name="count"/> handler invocations have returned
    /// normally.</summary>
    /// <param name="count">How many completions to wait for.</param>
    /// <param name="timeout">How long to wait before giving up.</param>
    /// <returns>True when they arrived, false on timeout.</returns>
    public Task<bool> WaitForCompletionsAsync(int count, TimeSpan timeout) =>
        Poll.UntilAsync(() => Completed >= count, timeout);

    /// <summary>A one-line summary for a failure message.</summary>
    public string Describe() => string.Create(
        CultureInfo.InvariantCulture,
        $"{_deliveries.Count} delivery/deliveries, {Completed} completed, {Running} running: "
        + $"[{string.Join(", ", _deliveries.Select(delivery => $"{delivery.TaskId}#{delivery.Attempt}"))}]");

    /// <summary>Called by <see cref="JournalTaskHandler"/> for every claimed task.</summary>
    internal async Task HandleAsync(
        QueuedTask task, ITaskQueue queue, IUnitOfWork unitOfWork, CancellationToken cancellationToken)
    {
        var attempt = _attempts.AddOrUpdate(task.TaskId, 1, (_, previous) => previous + 1);

        _deliveries.Enqueue(new TaskDelivery(
            task.Id, task.TaskId, task.QueueName, task.Priority, task.PoppedBy, attempt,
            DateTimeOffset.UtcNow));

        Interlocked.Increment(ref _running);

        try
        {
            await _behaviour(new TaskHandlerContext(task, queue, unitOfWork, attempt, cancellationToken));
        }
        finally
        {
            Interlocked.Decrement(ref _running);
        }

        // After the await and outside the finally on purpose: a behaviour that threw or was
        // cancelled did not complete, and the difference is what the exception and timeout tests
        // assert on.
        Interlocked.Increment(ref _completed);
    }
}

/// <summary>
/// The one <see cref="ITaskHandler"/> these tests register, delegating to a
/// <see cref="TaskJournal"/> the test owns.
/// <para>
/// It is the whole handler ceremony stage 2 documented, exercised for real: a scoped type
/// implementing the interface, a static queue name read off the type by the registration, and
/// constructor-injected scoped services from the task's own scope. If the runner resolved handlers
/// wrongly - from the wrong scope, or by interface instead of concrete type - this is where it
/// would show.
/// </para>
/// </summary>
internal sealed class JournalTaskHandler(
    TaskJournal journal, ITaskQueue queue, IUnitOfWork unitOfWork) : ITaskHandler
{
    /// <summary>The queue every test in this file uses.</summary>
    public const string Queue = "integration_tasks";

    /// <inheritdoc />
    public static string QueueName => Queue;

    /// <inheritdoc />
    public Task HandleAsync(QueuedTask task, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(task);

        return journal.HandleAsync(task, queue, unitOfWork, cancellationToken);
    }
}
