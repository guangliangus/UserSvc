namespace UserSvc.Application.Ports.Platform;

/// <summary>
/// One unit of async work as a claimed row hands it to its handler.
/// <para>
/// It is not the whole database row. <c>popped</c> is omitted because a task that reached a
/// handler is claimed by construction, and a field that is always <c>true</c> only invites a
/// handler to branch on it; <c>updated_at</c> / <c>created_by</c> / <c>updated_by</c> are audit
/// columns for an operator reading the table, not handler input.
/// </para>
/// </summary>
/// <param name="Id">The row's surrogate key - the handle for <see cref="ITaskQueue.DeleteAsync"/>
/// and <see cref="ITaskQueue.ReArmAsync"/>. It is how a handler names its own task, and the only
/// way to; nothing else here identifies the row to either call.</param>
/// <param name="QueueName">The runner pool that claimed the row.</param>
/// <param name="TaskId">The producer's idempotency key, unique within the queue.</param>
/// <param name="Priority">Claim order within the queue; higher was claimed first.</param>
/// <param name="PayloadJson">The handler's input, as a JSON object in raw text.</param>
/// <param name="DeliverOn">The delivery time this claim satisfied. On a retried task this is when
/// the previous attempt re-armed it, so <c>DeliverOn - CreatedAt</c> is how long the work has been
/// waiting rather than how long it has existed.</param>
/// <param name="CreatedAt">When the row was enqueued. The honest age of the work, whatever the
/// retries have done to <paramref name="DeliverOn"/>.</param>
/// <param name="PoppedAt">When this claim was taken, on the database clock.</param>
/// <param name="PoppedBy">The runner instance holding the claim.</param>
public sealed record QueuedTask(
    int Id,
    string QueueName,
    string TaskId,
    int Priority,
    string PayloadJson,
    DateTimeOffset DeliverOn,
    DateTimeOffset CreatedAt,
    DateTimeOffset? PoppedAt,
    string PoppedBy);

/// <summary>
/// A task to enqueue.
/// <para>
/// <see cref="TaskId"/> is the whole idempotency story: the queue holds at most one row per
/// (<see cref="QueueName"/>, <see cref="TaskId"/>), so a producer states what the work IS and does
/// not have to ask whether it is already queued.
/// </para>
/// </summary>
/// <param name="QueueName">The runner pool that will handle it. Required.</param>
/// <param name="TaskId">The idempotency key within that queue. Required.</param>
/// <param name="PayloadJson">The handler's input as a JSON object. Empty or whitespace is stored
/// as <c>{}</c>; anything else must be valid JSON or the database refuses the row.</param>
/// <param name="Priority">Claim order; higher is claimed first. Never negative.</param>
/// <param name="Delay">How long to hold the task back before a runner may claim it, or null for
/// "as soon as possible". A delay rather than an absolute time, so <c>deliver_on</c> is computed
/// as <c>now() + delay</c> by the database that will later test it - see the clock note on
/// <see cref="ITaskQueue"/>. A caller that genuinely means a wall-clock instant subtracts the
/// current time itself, and owns the skew that introduces.</param>
/// <param name="Actor">What to record in <c>created_by</c> / <c>updated_by</c>. This service has
/// no audit interceptor - every writer names its own actor.</param>
public sealed record TaskEnqueueRequest(
    string QueueName,
    string TaskId,
    string PayloadJson = "{}",
    int Priority = 0,
    TimeSpan? Delay = null,
    string Actor = "");

/// <summary>
/// The database-backed generic async task queue: the six operations a runner, a fixer and a
/// producer need against <c>identity.task_queues</c>.
/// <para>
/// <b>Why a database table and not a broker.</b> The row that causes async work and the row that
/// records the work commit in ONE transaction, so "the database changed" and "the work will be
/// attempted" cannot come apart. That is the same guarantee the outbox gives for published events,
/// and it is why RabbitMQ is not what this is. Delivery is at-least-once: a worker that crashes
/// between its side effect and its commit will see the task again, so <b>every handler must be
/// idempotent</b>.
/// </para>
/// <para>
/// <b>It is dormant by design, not dead by accident.</b> The runner ships with its worker count at
/// zero - the kill switch, and the shipped default - so nothing polls this table until a
/// deployment turns it on. The Go service being replaced ships the same way. Its only handler
/// there is the FCM topic sync, which belongs to the notification service and is deliberately not
/// ported, so user-svc has the mechanism and no production handler yet. What will use it: any
/// capability of this service that needs retried background work enqueued atomically with the
/// change that caused it.
/// </para>
/// <para>
/// <b>Transaction seam - this port does not batch into SaveChanges.</b> Every operation below
/// issues its statement immediately on the context's connection, because none of them can be
/// expressed through the change tracker: an unconditional enqueue needs ON CONFLICT DO NOTHING, a
/// claim needs FOR UPDATE SKIP LOCKED, and a SaveChanges-time duplicate would surface as a
/// unique-violation that aborts the caller's whole transaction instead of being ignored. They do
/// run inside the ambient transaction, so a producer that needs its business row and its enqueue
/// to be atomic must open one - <see cref="IUnitOfWork.ExecuteInTransactionAsync"/> - rather than
/// rely on a later SaveChanges to carry the enqueue.
/// </para>
/// <para>
/// <b>One clock, and it is the database's.</b> Every time comparison and every timestamp written
/// here is <c>now()</c> evaluated by PostgreSQL. Reading the clock in the process instead would
/// make a re-armed task's due time and the <c>deliver_on &lt;= now()</c> that tests it come from
/// two clocks that drift apart, so a backoff window would be as wrong as the pod's skew. (The Go
/// original mixes the two: its Pop compares against the database's <c>NOW()</c> while its re-arm
/// and its stale cutoff are computed from <c>time.Now()</c> in the pod.)
/// </para>
/// </summary>
public interface ITaskQueue
{
    /// <summary>
    /// Enqueues tasks, ignoring any whose (queue, task id) slot is already taken.
    /// <para>
    /// The deduplication is what lets a producer push unconditionally from every write site that
    /// could need the work: the first writer wins and concurrent writers are harmless, with no
    /// read-then-insert race in between.
    /// </para>
    /// </summary>
    /// <param name="tasks">What to enqueue. An empty collection is a no-op, not an error.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>How many rows were actually inserted - so <c>0</c> means every task was already
    /// queued, which is a success and not a failure.</returns>
    Task<int> PushIfNotExistsAsync(
        IReadOnlyCollection<TaskEnqueueRequest> tasks, CancellationToken cancellationToken);

    /// <summary>
    /// Claims up to <paramref name="limit"/> due tasks from one queue, atomically.
    /// <para>
    /// One statement, holding <c>FOR UPDATE SKIP LOCKED</c>: concurrent pollers - in this pod or
    /// any other - step over each other's locked rows instead of blocking on them, so no row is
    /// ever handed to two workers and no poller waits for another. Splitting it into a select and
    /// an update would reintroduce exactly the race the queue exists to avoid.
    /// </para>
    /// <para>
    /// <b>A runner claims outside any transaction</b>, so the claim commits at once and is
    /// immediately visible to every other pod. Claiming inside a long-lived transaction is legal
    /// and safe - other pollers step over the locked rows rather than blocking - but the claim
    /// stays invisible until that transaction commits, so the rows are unavailable to everyone and
    /// recoverable by nobody for its whole duration. If a caller does need a transaction here it
    /// must come from <see cref="IUnitOfWork.ExecuteInTransactionAsync"/>: this context retries
    /// transient failures, and the retrying execution strategy refuses to run a query inside a
    /// transaction the caller opened by hand.
    /// </para>
    /// </summary>
    /// <param name="queueName">The queue to claim from.</param>
    /// <param name="limit">The most rows to claim. Zero or less claims nothing.</param>
    /// <param name="poppedBy">The claiming runner's identifier, recorded on the row so an operator
    /// can tie a stuck task back to a pod.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The claimed rows, in claim order. Empty when nothing is due.</returns>
    Task<IReadOnlyList<QueuedTask>> PopAsync(
        string queueName, int limit, string poppedBy, CancellationToken cancellationToken);

    /// <summary>
    /// Removes a row terminally - on success, and equally on giving up after the last attempt.
    /// <para>
    /// A physical delete, deliberately, against this project's "avoid physical deletes"
    /// convention: a queue row is transient work rather than a record, what the task did is
    /// recorded by the handler in its own tables, and the (queue, task id) slot has to be freed or
    /// the same subject could never be enqueued again. The script header argues it in full.
    /// </para>
    /// </summary>
    /// <param name="id">The row, as <see cref="QueuedTask.Id"/> handed it to the handler.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>True when a row was removed; false when it was already gone, which is what a
    /// duplicate delivery of a finished task looks like.</returns>
    Task<bool> DeleteAsync(int id, CancellationToken cancellationToken);

    /// <summary>
    /// Releases a claimed row back to the queue with a later delivery time: retry with backoff.
    /// <para>
    /// The claim is cleared as well as the delivery time moved, so the next runner that picks the
    /// row up owns it cleanly rather than inheriting a claim from whoever gave up. The attempt
    /// budget is NOT kept here - it belongs to whatever the handler is reconciling, because only
    /// the handler knows whether an attempt made progress.
    /// </para>
    /// </summary>
    /// <param name="id">The row to release.</param>
    /// <param name="delay">How long from now - the database's now - before it may be claimed
    /// again. <see cref="TimeSpan.Zero"/> means immediately; a negative delay is accepted and also
    /// means immediately, which is what makes "give this straight back" expressible.</param>
    /// <param name="actor">What to record in <c>updated_by</c>.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>True when a row was released; false when it no longer exists.</returns>
    Task<bool> ReArmAsync(
        int id, TimeSpan delay, string actor, CancellationToken cancellationToken);

    /// <summary>
    /// Reclaims rows that have been claimed longer than <paramref name="timeout"/>, so a crashed
    /// or OOM-killed pod cannot pin work forever.
    /// <para>
    /// It releases the claim and touches nothing else. In particular it does not move any attempt
    /// counter: a worker that had already made progress before dying must not lose its retry
    /// budget for having died, and a worker that had not made progress has not spent any. It also
    /// leaves the delivery time alone - a claimed row is already due, so the reclaimed task is
    /// claimable at once AND keeps its place in the claim order rather than going behind everything
    /// that arrived while it was stuck. (The Go original stamps <c>deliver_on</c> with the current
    /// time here, which costs the recovered task its position.)
    /// </para>
    /// <para>
    /// Not scoped to a queue, because a crashed pod has to be recovered from whatever queue it was
    /// serving and nothing left behind says which one that was.
    /// </para>
    /// </summary>
    /// <param name="timeout">How long a claim may stand before it is presumed abandoned. Zero or
    /// less reclaims nothing - the switch that turns the reclaim off.</param>
    /// <param name="actor">What to record in <c>updated_by</c> on the rows it reclaims, so the
    /// reclaim is distinguishable from a handler's own re-arm when someone reads the table.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>How many rows were reclaimed. Anything above zero is worth a warning in the log:
    /// it means a worker died holding work.</returns>
    Task<int> RecoverStaleAsync(TimeSpan timeout, string actor, CancellationToken cancellationToken);

    /// <summary>
    /// How many rows of one queue are claimable right now - unclaimed and due.
    /// <para>
    /// The queue-depth metric. It deliberately does not count claimed rows or rows waiting on a
    /// backoff: a number that included those could not distinguish a healthy queue with slow
    /// retries from a stalled one.
    /// </para>
    /// </summary>
    /// <param name="queueName">The queue to measure.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The claimable row count.</returns>
    Task<int> CountPendingAsync(string queueName, CancellationToken cancellationToken);
}
