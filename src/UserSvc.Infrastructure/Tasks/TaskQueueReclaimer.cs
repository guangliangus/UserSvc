using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Infrastructure.Tasks;

/// <summary>
/// Releases claims that no worker is honouring any more, so a pod that was OOM-killed or lost its
/// node cannot pin work forever. (The Go service calls this the task fixer.)
/// <para>
/// <b>Why it is needed at all.</b> A claim is a row with <c>popped = true</c> and nothing else -
/// no lease to expire, no heartbeat to miss. That is what makes the claim itself a single cheap
/// statement, and the price is that a worker which dies mid-task leaves a row no one will ever
/// look at again. This is the counterweight: after <c>Tasks:StalePoppedTimeout</c> the claim is
/// presumed abandoned and released.
/// </para>
/// <para>
/// <b>It does not touch any attempt counter, and that is a decision rather than an omission.</b>
/// Only a handler knows whether an attempt made progress - a worker that had already written its
/// side effect before dying deserves to keep the budget it spent, and one that died before doing
/// anything has spent none. Charging an attempt here would take a retry away from the tasks most
/// likely to need one, on the evidence that a pod died.
/// </para>
/// <para>
/// <b>It is not scoped to a queue</b>, because a dead pod has to be recovered from whatever queues
/// it was serving and nothing it left behind says which those were - see
/// <see cref="ITaskQueue.RecoverStaleAsync"/>.
/// </para>
/// <para>
/// <b>Disabled means returned, not idling.</b> When the reclaim is switched off this method
/// returns, and <see cref="BackgroundService.StopAsync"/> then completes immediately because the
/// task it awaits has already finished. The Go equivalent has a real bug here: its Start returns
/// early without closing the done channel its WaitDone selects on, so disabling the fixer with
/// <c>FCM_SYNC_FIXER_INTERVAL=0</c> adds the whole shutdown timeout to every SIGTERM. The shape
/// cannot occur here, because the framework owns both halves.
/// </para>
/// </summary>
public sealed class TaskQueueReclaimer(
    IServiceScopeFactory scopeFactory,
    IOptions<TaskQueueOptions> options,
    TimeProvider time,
    ILogger<TaskQueueReclaimer> logger) : BackgroundService
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
            // Shutdown.
        }
        catch (Exception ex)
        {
            // As in the runner: an exception out of ExecuteAsync stops the whole host by default,
            // so the reclaim failing must cost the reclaim and nothing else.
            logger.LogError(ex, "The task queue reclaim stopped unexpectedly; abandoned claims will not be released until this pod restarts.");
        }
    }

    private async Task RunAsync(CancellationToken stoppingToken)
    {
        TaskQueueOptions settings;

        try
        {
            settings = options.Value;
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "Configuration section {Section} is invalid, so the task queue reclaim will not start. Everything else in this service is unaffected.",
                TaskQueueOptions.SectionName);

            return;
        }

        // The same kill switch as the runner, checked here rather than inherited from whoever
        // registered this service. Reclaiming is worker work: a pod with no workers is not part of
        // the queue at all (decision 02's two deployment shapes), and it should not be issuing an
        // UPDATE against a table it never reads.
        if (settings.WorkerCount <= 0)
        {
            logger.LogInformation(
                "Task queue reclaim is off with the runner: {Section}:{Setting} is {Value}.",
                TaskQueueOptions.SectionName,
                nameof(TaskQueueOptions.WorkerCount),
                settings.WorkerCount);

            return;
        }

        if (settings.StalePoppedTimeout <= TimeSpan.Zero || settings.ReclaimInterval <= TimeSpan.Zero)
        {
            logger.LogWarning(
                "Task queue reclaim is off: {Section}:{Timeout} is {TimeoutValue} and {Section}:{Interval} is {IntervalValue}. A worker that dies mid-task will pin its row until this pod is reconfigured.",
                TaskQueueOptions.SectionName,
                nameof(TaskQueueOptions.StalePoppedTimeout),
                settings.StalePoppedTimeout,
                TaskQueueOptions.SectionName,
                nameof(TaskQueueOptions.ReclaimInterval),
                settings.ReclaimInterval);

            return;
        }

        // Same shape as the runner id, with a fixed prefix instead of a queue name because the
        // reclaim is not queue-scoped. It lands in updated_by, which is what tells someone reading
        // the table that a row was released by the reclaim rather than re-armed by its own handler.
        var reclaimerId = "task-queue-reclaimer-" + Guid.NewGuid();

        logger.LogInformation(
            "Task queue reclaim starting as {ReclaimerId}: releasing claims older than {Timeout} every {Interval}.",
            reclaimerId,
            settings.StalePoppedTimeout,
            settings.ReclaimInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ReclaimAsync(settings, reclaimerId, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // The next tick retries. A reclaim that fails delays recovery; a reclaim that stops
                // means no abandoned claim is ever released again on this pod.
                logger.LogError(ex, "Task queue reclaim failed; retrying on the next tick.");
            }

            // A delay after the work rather than a PeriodicTimer, so the interval is the gap
            // between runs and cannot queue up ticks behind a slow UPDATE. It is also the same
            // waiting primitive the runner uses - one shape, one seam a test can drive - and unlike
            // a timer it is woken by the stopping token immediately rather than at the next tick.
            await Task.Delay(settings.ReclaimInterval, time, stoppingToken);
        }
    }

    private async Task ReclaimAsync(
        TaskQueueOptions settings, string reclaimerId, CancellationToken stoppingToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        // A TimeSpan and not a cutoff instant: the comparison is popped_at < now() - timeout
        // evaluated by PostgreSQL, so a pod whose clock is wrong cannot reclaim rows early. (The
        // Go original computes the cutoff from the pod's own clock.)
        var released = await queue.RecoverStaleAsync(settings.StalePoppedTimeout, reclaimerId, stoppingToken);

        if (released > 0)
        {
            // A warning, because zero is the healthy value: anything above it means work was
            // claimed and not finished, and the number is how much.
            //
            // The message deliberately does not say "that many workers died", which is what it
            // used to say and what it is wrong about in two of the three cases. A released claim
            // means the row was held past the timeout, and that happens when the worker died, when
            // the handler threw and left the row for exactly this path (ITaskHandler's contract),
            // and when the handler is STILL RUNNING and simply slower than the timeout - measured,
            // and the reason Tasks:TaskTimeout must stay below Tasks:StalePoppedTimeout. From
            // here the three are indistinguishable, so the line says what it knows.
            logger.LogWarning(
                "Task queue reclaim released {Count} claim(s) held longer than {Timeout}. Each of those tasks will be delivered again; a worker died, threw, or is still running past the timeout.",
                released,
                settings.StalePoppedTimeout);
        }
    }
}
