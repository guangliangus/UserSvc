namespace UserSvc.Application.Ports.Platform;

/// <summary>
/// What one queue's worker does with a claimed task. Exactly one implementation per
/// <see cref="QueueName"/>, and the runner refuses to poll a queue that has two.
/// <para>
/// <b>THE HANDLER MUST BE IDEMPOTENT. This is not a quality goal, it is the contract.</b>
/// Delivery is at-least-once and the reason is structural, not a bug anyone can fix: a handler
/// makes a side effect (a row written, a message sent, a remote system called) and then records
/// that it made it. Between those two moments the pod can be OOM-killed, the node can go away, or
/// the network can drop the commit. The queue row is then still claimed, the reclaim releases it,
/// and <b>the same task is handed to a worker again with the side effect already done</b>. A
/// handler that assumes it sees each task once will double-charge, double-send, or crash on a
/// duplicate key the first time a pod dies - which it will, on the first rolling update.
/// So: check before you act, or make the act itself repeatable
/// (upsert, <c>ON CONFLICT DO NOTHING</c>, an idempotency key the remote system honours).
/// </para>
/// <para>
/// <b>The handler owns its own queue write - the runner deliberately infers nothing.</b>
/// <see cref="HandleAsync"/> returns a bare <see cref="Task"/> and not a result, and a .NET
/// author's instinct - return an outcome and let the runner delete or re-arm - is what this
/// contract is refusing, for three reasons:
/// </para>
/// <list type="number">
/// <item><description><b>Atomicity.</b> The handler's own write and its
/// <see cref="ITaskQueue.DeleteAsync"/> can share one transaction, and where the work IS a
/// database change that is the whole point of a database-backed queue. A runner deleting the row
/// afterwards is necessarily a second transaction, so the crash window between them would be
/// permanent and unclosable - the queue would guarantee less than the table it is built on.
/// </description></item>
/// <item><description><b>"Failed" is not one thing.</b> A malformed payload will fail identically
/// forever and must end at <see cref="ITaskQueue.DeleteAsync"/>; a remote 503 must come back with
/// backoff through <see cref="ITaskQueue.ReArmAsync"/>; a partial success must record what
/// succeeded and retry only the rest. Only the handler can tell those apart, and a runner reading
/// a boolean cannot.</description></item>
/// <item><description><b>The attempt budget is domain state.</b> Whether an attempt made progress
/// is knowable only inside the handler, so the counter belongs in the handler's own table (or its
/// payload) - see the note on <see cref="ITaskQueue.RecoverStaleAsync"/> for why neither the
/// re-arm nor the reclaim touches it. <c>Tasks:MaxAttempts</c> is the configured budget; comparing
/// against it, and calling <see cref="ITaskQueue.DeleteAsync"/> when it is spent, is the handler's
/// job. Terminal failure is a delete, not a row left behind: it frees the (queue, task id) slot so
/// the same subject can be enqueued again when something changes.</description></item>
/// </list>
/// <para>
/// <b>What the runner does with an exception.</b> It logs it and moves on: the row stays claimed,
/// and it becomes claimable again only when the reclaim releases it - <c>Tasks:StalePoppedTimeout</c>
/// later, ten minutes by default. So an escaping exception is a slow retry, never a lost task, and
/// never a stopped queue. A handler that wants a fast retry must catch its own failure and call
/// <see cref="ITaskQueue.ReArmAsync"/> with a delay; a handler that throws is choosing the reclaim.
/// </para>
/// <para>
/// <b>And that retry is UNBOUNDED. There is no ceiling anywhere in the mechanism.</b> Measured, on
/// the real host against the real database: a handler that threw on every delivery was handed the
/// same row eleven times in forty seconds - once per <c>Tasks:StalePoppedTimeout</c> plus one
/// reclaim tick - and <c>Tasks:MaxAttempts</c>, set to 2 for that run, changed nothing, because
/// nothing on this path counts. Left alone with the shipped intervals a poison row is retried
/// roughly every eleven minutes for as long as the database exists, and the only thing that ends it
/// is somebody's <see cref="ITaskQueue.DeleteAsync"/> - the handler's, on its own attempt budget, or
/// an operator's by hand. That is why the budget in the third point below is not a nicety: throwing
/// is a fine way to say "retry me", and a terrible way to say "give up on me".
/// </para>
/// <para>
/// <b>No implementation exists yet, and that is deliberate.</b> The Go service's only handler is
/// its FCM topic sync, which belongs to the notification service, so user-svc ships this mechanism
/// dormant - <c>Tasks:WorkerCount</c> is 0 by default and nothing polls. This interface is the
/// seam the first capability needing retried background work implements; registering it is one
/// call to <c>AddTaskHandler&lt;T&gt;()</c> and no change to the runner.
/// </para>
/// </summary>
public interface ITaskHandler
{
    /// <summary>
    /// The queue this handler serves - the same string producers pass as
    /// <see cref="TaskEnqueueRequest.QueueName"/>.
    /// <para>
    /// <b>Static</b>, because the queue a handler serves is a fact about the type and not about an
    /// instance, and because the runner must know every queue name before it constructs anything:
    /// the registration reads it off the type, so a handler whose constructor needs configuration
    /// it has not got breaks its own queue's tasks and no other queue's discovery. (Go declares it
    /// as an instance method for the plain reason that Go interfaces have no static members.)
    /// </para>
    /// </summary>
    static abstract string QueueName { get; }

    /// <summary>
    /// Handles one claimed task. See the idempotency and ownership rules on
    /// <see cref="ITaskHandler"/> - both are load-bearing.
    /// </summary>
    /// <param name="task">The claimed row. <see cref="QueuedTask.Id"/> is the handle for this
    /// handler's own <see cref="ITaskQueue.DeleteAsync"/> or <see cref="ITaskQueue.ReArmAsync"/>
    /// call.</param>
    /// <param name="cancellationToken">
    /// <b>This task's own deadline, and NOT the host's shutdown token.</b> The two are deliberately
    /// never linked: a shutdown does not interrupt work already in flight - it stops new claims and
    /// then waits - so a handler that sees this token cancelled is over
    /// <c>Tasks:TaskTimeout</c> and nothing else. That makes the distinction actionable: cancelled
    /// means "you took too long", so stop where you are and leave the row claimed for the reclaim,
    /// rather than treating it as "we are going down" and rushing a write that nothing will wait
    /// for. It also means the handler must actually pass this token down to its own I/O, or the
    /// timeout is a number in a config file that does nothing.
    /// </param>
    /// <returns>A task that completes when this attempt is over, successfully or not.</returns>
    Task HandleAsync(QueuedTask task, CancellationToken cancellationToken);
}
