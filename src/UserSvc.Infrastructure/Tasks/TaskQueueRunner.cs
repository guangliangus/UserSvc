using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Infrastructure.Tasks;

/// <summary>
/// Polls <c>identity.task_queues</c> and runs what it claims: one independent loop per registered
/// queue name, each fanning claimed rows out to at most <c>Tasks:WorkerCount</c> concurrent
/// handlers.
/// <para>
/// <b>It is in-process and it does not coordinate.</b> Every pod runs its own loops and they share
/// the queue safely because the claim is a single <c>FOR UPDATE SKIP LOCKED</c> statement - pods
/// step over each other's locked rows instead of blocking on them. There is no leader, no lease
/// and nothing to configure per replica: scaling the deployment scales the workers.
/// </para>
/// <para>
/// <b>Dormant by default.</b> <c>Tasks:WorkerCount</c> ships at 0 and no handler is registered
/// yet, so on today's build this service logs one line at startup and returns. Both facts are
/// checked here rather than by whoever registers the service, so neither can be defeated by a
/// caller forgetting to look.
/// </para>
/// <para>
/// <b>Two levels of exception isolation, for two different disasters.</b> Per task, so one bad
/// payload cannot stop the queue; per loop iteration, so a failed claim or a broken
/// <c>DbContext</c> cannot end the loop. And around the whole of
/// <see cref="ExecuteAsync"/>, because <c>BackgroundServiceExceptionBehavior.StopHost</c> is the
/// default: an exception escaping a hosted service's <c>ExecuteAsync</c> stops the entire host, so
/// here an unguarded throw would take every HTTP endpoint down with the queue. That is a stronger
/// reason than the Go original's, which merely loses its poll loop to a panic.
/// </para>
/// <para>
/// <b>Why the mechanics look nothing like the Go version.</b> Go hand-rolls its slot accounting
/// from a mutex, an integer, a size-1 coalescing channel and a defensive 200 ms poll to cover the
/// signals that channel drops. All four are replaced by one <see cref="SemaphoreSlim"/>:
/// <c>CurrentCount</c> IS the free-slot count with no lock of our own, and the drain is
/// <c>Task.WhenAll</c> over the tasks we started rather than a counter someone has to poll. The
/// stop signal is the framework's <c>stoppingToken</c>, and the sleep is
/// <c>Task.Delay(..., TimeProvider, token)</c>, which a stop wakes immediately - so there is no
/// interval-length delay between "stop" and the loop noticing, and no signal to lose.
/// </para>
/// </summary>
public sealed class TaskQueueRunner(
    IServiceScopeFactory scopeFactory,
    IEnumerable<TaskHandlerRegistration> registrations,
    IOptions<TaskQueueOptions> options,
    TimeProvider time,
    ILogger<TaskQueueRunner> logger) : BackgroundService
{
    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await RunAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // The host is going down. Not a failure, and nothing to say that the drain has not
            // already said.
        }
        catch (Exception ex)
        {
            // The outermost net. Anything reaching here would otherwise stop the whole host,
            // because that is what BackgroundServiceExceptionBehavior.StopHost does by default -
            // so the task queue would take every HTTP endpoint with it.
            logger.LogError(ex, "The task queue runner stopped unexpectedly; this pod claims no more work until it restarts.");
        }
    }

    private async Task RunAsync(CancellationToken stoppingToken)
    {
        // First read of the section, and the reason this is inside a method rather than a field:
        // .Value is where ValidateDataAnnotations runs, so a bad Tasks:* value throws HERE, is
        // logged with the section named, and costs the queue only. In a field initializer the same
        // typo would be thrown while the host was being built.
        TaskQueueOptions settings;

        try
        {
            settings = options.Value;
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "Configuration section {Section} is invalid, so the task queue runner will not start. Everything else in this service is unaffected.",
                TaskQueueOptions.SectionName);

            return;
        }

        if (settings.WorkerCount <= 0)
        {
            // The kill switch, and the shipped default. Deliberately Information and deliberately
            // unconditional: "is this pod working the queue" is the first question asked during an
            // incident, and the answer has to be in the boot log rather than inferred from the
            // absence of other lines.
            logger.LogInformation(
                "Task queue runner is off: {Section}:{Setting} is {Value}, so this pod claims no background work. Nothing is polled and no timer runs.",
                TaskQueueOptions.SectionName,
                nameof(TaskQueueOptions.WorkerCount),
                settings.WorkerCount);

            return;
        }

        var queues = Assignments();

        if (queues.Count == 0)
        {
            // Worth its own line rather than silence. An operator who has just set WorkerCount to
            // 4 has every reason to believe work is being done, and on a build with no handler
            // registered none is.
            logger.LogInformation(
                "Task queue runner has no handlers registered, so there is nothing to poll even though {Section}:{Setting} is {Value}. Register one with AddTaskHandler<T>().",
                TaskQueueOptions.SectionName,
                nameof(TaskQueueOptions.WorkerCount),
                settings.WorkerCount);

            return;
        }

        logger.LogInformation(
            "Task queue runner starting: queues=[{Queues}] workers={WorkerCount} per queue, max_attempts={MaxAttempts}, poll={ShortPoll}/{LongPoll}, task_timeout={TaskTimeout}, drain={DrainTimeout}.",
            string.Join(", ", queues.Select(queue => queue.QueueName)),
            settings.WorkerCount,
            settings.MaxAttempts,
            settings.ShortPollInterval,
            settings.LongPollInterval,
            settings.TaskTimeout,
            settings.DrainTimeout);

        // One loop per queue, all awaited together: ExecuteAsync completes only when every loop
        // has stopped AND drained, which is what makes StopAsync a real drain rather than a
        // request to start one.
        await Task.WhenAll(queues.Select(queue => PollQueueAsync(queue, settings, stoppingToken)));
    }

    /// <summary>
    /// The registered handlers, one per queue name.
    /// <para>
    /// A queue with two handlers is a wiring mistake with no safe reading - whichever handler were
    /// picked, the other's tasks would silently never run - so that queue is refused and named,
    /// and the other queues start normally.
    /// </para>
    /// </summary>
    private List<TaskHandlerRegistration> Assignments()
    {
        var assignments = new List<TaskHandlerRegistration>();

        foreach (var group in registrations.GroupBy(entry => entry.QueueName, StringComparer.Ordinal))
        {
            var candidates = group.ToList();

            if (candidates.Count > 1)
            {
                logger.LogError(
                    "Queue {QueueName} has {Count} handlers registered ({Handlers}), so it will not be polled. Exactly one handler serves one queue.",
                    group.Key,
                    candidates.Count,
                    string.Join(", ", candidates.Select(entry => entry.HandlerType.FullName)));

                continue;
            }

            assignments.Add(candidates[0]);
        }

        return assignments;
    }

    private async Task PollQueueAsync(
        TaskHandlerRegistration queue, TaskQueueOptions settings, CancellationToken stoppingToken)
    {
        // Go's shape, kept: the queue name so a row says which pool claimed it, and a fresh GUID so
        // it says which process. It goes into popped_by and is how an operator ties a stuck row
        // back to a pod, so it must be stable for the life of the loop - computed once, here.
        var runnerId = queue.QueueName + "-" + Guid.NewGuid();

        // Not disposed, and not by omission. A straggler that outlives a timed-out drain calls
        // Release in its finally block; on a disposed semaphore that throws ObjectDisposedException
        // from inside a finally, which faults a task nobody is awaiting any more. SemaphoreSlim
        // only needs disposal for the AvailableWaitHandle this code never touches.
        var slots = new SemaphoreSlim(settings.WorkerCount, settings.WorkerCount);
        var inFlight = new List<Task>();
        var depth = new QueueDepthSignal(time, logger, settings.LongPollInterval);

        logger.LogInformation(
            "Queue {QueueName} is being polled by runner {RunnerId} with {WorkerCount} worker slots.",
            queue.QueueName,
            runnerId,
            settings.WorkerCount);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await PollOnceAsync(queue, settings, runnerId, slots, inFlight, depth, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    // Loop-level isolation. Resolving the queue port, the claim, the dispatch: any
                    // of them can fail for a reason that clears on its own (a database failover, a
                    // pool exhausted by something else), and none of them may end the loop, because
                    // a loop that ends never restarts without a redeploy.
                    logger.LogError(ex, "Poll iteration failed on queue {QueueName}; retrying after the short interval.", queue.QueueName);
                    await Task.Delay(settings.ShortPollInterval, time, stoppingToken);
                }
            }
        }
        finally
        {
            await DrainAsync(queue.QueueName, inFlight, settings);
        }
    }

    private async Task PollOnceAsync(
        TaskHandlerRegistration queue,
        TaskQueueOptions settings,
        string runnerId,
        SemaphoreSlim slots,
        List<Task> inFlight,
        QueueDepthSignal depth,
        CancellationToken stoppingToken)
    {
        // Finished tasks are dropped before anything else, so this list is the in-flight set and
        // not a log of everything this pod has ever run. Left ungroomed it would grow for the life
        // of the process and the drain would walk it all.
        inFlight.RemoveAll(task => task.IsCompleted);

        // Reported before the slot check and from inside this loop, both deliberately. Before,
        // because a saturated pool is exactly when backlog matters and a depth signal that stops
        // when the workers are busy reports zero during the only incident it exists for. Inside,
        // because it must not outlive the loop: the Go version runs the equivalent in a bare
        // goroutine with no stop channel, so it keeps issuing COUNT(*) after shutdown has begun -
        // against a connection pool that is closing - and is the one thing its Stop cannot account
        // for.
        await depth.ReportAsync(scopeFactory, queue.QueueName, stoppingToken);

        // The batch size IS the number of free slots. Claiming more would be claiming rows this pod
        // cannot start, and a claimed row is invisible to every other pod until it is done or
        // reclaimed - so an over-large batch does not queue work locally, it hides it from the
        // pods that could have run it.
        var batchSize = slots.CurrentCount;

        if (batchSize < 1)
        {
            await Task.Delay(settings.ShortPollInterval, time, stoppingToken);

            return;
        }

        var claimed = await ClaimAsync(queue.QueueName, batchSize, runnerId, stoppingToken);

        if (claimed is null)
        {
            // The claim failed and said why in the log. Short interval, because whatever broke is
            // more likely transient than not, and a queue that backs off ten seconds per failure
            // recovers ten seconds late for no reason.
            await Task.Delay(settings.ShortPollInterval, time, stoppingToken);

            return;
        }

        if (claimed.Count == 0)
        {
            // Nothing due. This is the idle state and the long interval is what makes an idle pod
            // cheap: one statement per queue per interval.
            await Task.Delay(settings.LongPollInterval, time, stoppingToken);

            return;
        }

        foreach (var task in claimed)
        {
            // Cannot block: we claimed at most CurrentCount rows and this loop is the only thing
            // that takes a slot. It is still an acquire rather than a decrement, so the invariant
            // is enforced by the semaphore rather than by this comment staying true. A stop landing
            // mid-dispatch leaves the rest of the batch claimed and unstarted, which is again the
            // reclaim's business rather than a case to handle here.
            await slots.WaitAsync(stoppingToken);
            inFlight.Add(RunTaskAsync(queue, task, settings, slots));
        }

        // No delay: come straight back and claim again with whatever slots are still free. That is
        // what keeps a full queue moving at the speed of the handlers rather than the speed of the
        // poll interval.
    }

    /// <summary>
    /// Claims a batch, or answers null when the claim failed.
    /// <para>
    /// The scope is per poll and disposed immediately, so the claim's own <c>DbContext</c> - and
    /// the connection it took from the pool - are not held for as long as the tasks run. And the
    /// claim runs in no transaction of ours, so it commits at once and is instantly visible to
    /// every other pod: claiming inside a long transaction is safe but keeps the rows unavailable
    /// to everyone and recoverable by nobody until it commits.
    /// </para>
    /// </summary>
    private async Task<IReadOnlyList<QueuedTask>?> ClaimAsync(
        string queueName, int batchSize, string runnerId, CancellationToken stoppingToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

            return await queue.PopAsync(queueName, batchSize, runnerId, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Rethrown so the loop ends rather than short-polling into a shutdown. A statement
            // cancelled here can still have committed - the claim is one statement, and losing the
            // connection after it commits but before its rows are read leaves them claimed by a
            // runner that never saw them. That is the rarest way to strand a row and it needs no
            // special handling: it is the same state a killed pod leaves, and the reclaim is what
            // clears it.
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to claim tasks from queue {QueueName}.", queueName);

            return null;
        }
    }

    /// <summary>
    /// Runs one task to completion, whatever it does. This method never throws and never faults its
    /// task: it is started fire-and-forget and only the drain ever looks at it again.
    /// </summary>
    private async Task RunTaskAsync(
        TaskHandlerRegistration queue, QueuedTask task, TaskQueueOptions settings, SemaphoreSlim slots)
    {
        // The task's own deadline, and NOT linked to the host's stoppingToken. That is the whole
        // cancellation design: a stop must not interrupt work already in flight (it stops new
        // claims and then waits), so the only thing that can cancel a handler is its own timeout -
        // which makes "cancelled" mean exactly one thing to the handler. The same reasoning as
        // RedisFailure's: a cancellation the caller asked for and a cancellation nobody asked for
        // are different events, and code that cannot tell them apart reports the wrong one.
        using var deadline = settings.TaskTimeout > TimeSpan.Zero
            ? new CancellationTokenSource(settings.TaskTimeout, time)
            : null;

        try
        {
            // A scope per task, not per poll: handlers own their own database writes, a DbContext
            // is not thread-safe, and WorkerCount of them run at once. Sharing one scope across a
            // batch would corrupt the change tracker under any real concurrency.
            await using var scope = scopeFactory.CreateAsyncScope();

            // Resolved by concrete type, so only THIS queue's handler is constructed. Resolving
            // every ITaskHandler and picking by name would construct all of them per task, and a
            // handler whose own configuration is missing would then break another queue's tasks.
            var handler = (ITaskHandler)scope.ServiceProvider.GetRequiredService(queue.HandlerType);

            await handler.HandleAsync(task, deadline?.Token ?? CancellationToken.None);
        }
        catch (OperationCanceledException) when (deadline is { IsCancellationRequested: true })
        {
            logger.LogWarning(
                "Task {TaskId} on queue {QueueName} (row {RowId}) exceeded {TaskTimeout} and was cancelled. Its row stays claimed until the reclaim releases it after {StalePoppedTimeout}.",
                task.TaskId,
                queue.QueueName,
                task.Id,
                settings.TaskTimeout,
                settings.StalePoppedTimeout);
        }
        catch (Exception ex)
        {
            // Per-task isolation. The row is left claimed on purpose: the handler owns the queue
            // row, so the runner deleting or re-arming it here would be the runner deciding
            // something only the handler knows. Leaving it claimed makes the reclaim the retry
            // path - slow (StalePoppedTimeout) but certain. A handler wanting a fast retry catches
            // its own failure and re-arms with a backoff.
            //
            // That retry has NO CEILING, and this log line is the only trace of it. Nothing here or
            // in the reclaim counts attempts, so a handler that always throws is redelivered once
            // per StalePoppedTimeout forever - measured on the real host: eleven deliveries of one
            // row in forty seconds at a 3s timeout, with MaxAttempts=2 having no effect at all. The
            // MaxAttempts value is in the startup line for operators and is enforced by handlers,
            // never here. See ITaskHandler.
            logger.LogError(
                ex,
                "Handler {Handler} threw on task {TaskId} of queue {QueueName} (row {RowId}). The row stays claimed until the reclaim releases it after {StalePoppedTimeout}.",
                queue.HandlerType.Name,
                task.TaskId,
                queue.QueueName,
                task.Id,
                settings.StalePoppedTimeout);
        }
        finally
        {
            slots.Release();
        }
    }

    /// <summary>
    /// Waits for the tasks already running, bounded by <c>Tasks:DrainTimeout</c>.
    /// <para>
    /// This runs after the loop has stopped claiming, which is the ordering the Go service spells
    /// out in its shutdown path and which an ASP.NET host gives for free: the framework cancels
    /// <c>stoppingToken</c> for every hosted service before it awaits any of their
    /// <c>StopAsync</c>, so "stop taking new work" happens for all of them first and the awaits
    /// that follow are the drain.
    /// </para>
    /// </summary>
    private async Task DrainAsync(string queueName, List<Task> inFlight, TaskQueueOptions settings)
    {
        inFlight.RemoveAll(task => task.IsCompleted);

        if (inFlight.Count == 0)
        {
            return;
        }

        logger.LogInformation(
            "Queue {QueueName} has stopped claiming and is draining {Count} task(s) already in flight, for up to {DrainTimeout}.",
            queueName,
            inFlight.Count,
            settings.DrainTimeout);

        // Deliberately not passing stoppingToken: it is already cancelled, and the point of the
        // drain is that a stop does not interrupt work in flight.
        var all = Task.WhenAll(inFlight);

        if (settings.DrainTimeout <= TimeSpan.Zero)
        {
            await all;

            return;
        }

        try
        {
            await all.WaitAsync(settings.DrainTimeout, time);
        }
        catch (TimeoutException)
        {
            logger.LogWarning(
                "Queue {QueueName} still had {Count} task(s) running after {DrainTimeout}; shutdown is continuing without them. Their rows stay claimed and the reclaim releases them after {StalePoppedTimeout}.",
                queueName,
                inFlight.Count(task => !task.IsCompleted),
                settings.DrainTimeout,
                settings.StalePoppedTimeout);
        }
    }
}
