using System.ComponentModel.DataAnnotations;

namespace UserSvc.Infrastructure.Tasks;

/// <summary>
/// How this pod runs the generic async task queue (<c>identity.task_queues</c>,
/// db/0014_task_queues.sql).
/// <para>
/// <b>Bound with <c>ValidateDataAnnotations()</c> and deliberately WITHOUT
/// <c>ValidateOnStart()</c>.</b> Every value here has a working default and the whole section is
/// optional, so a deployment that never configures it must boot and serve HTTP exactly as it does
/// today. Validation therefore happens on the first read, which is inside
/// <see cref="TaskQueueRunner"/> and <see cref="TaskQueueReclaimer"/> - and both catch it, log the
/// section by name and stop polling, so a typo in <c>Tasks:ShortPollInterval</c> costs the queue
/// and nothing else (docs/architecture.md, "a missing capability may only break itself"). Reading
/// <c>IOptions.Value</c> in a constructor or field initializer would undo all of that: a hosted
/// service is constructed while the host is being built, so the throw would land before the host
/// starts - which is why tests/UserSvc.ArchitectureTests/OptionsReadSiteTests.cs fails the build on
/// it.
/// </para>
/// <para>
/// <b>The defaults are the Go service's defaults</b>, so a pod moved from one implementation to the
/// other behaves the same before anyone touches a config map. The names differ where the Go name
/// described its one FCM caller rather than the mechanism; each is noted below.
/// </para>
/// <para>
/// <b>Read once, when the loop starts.</b> Both services take a snapshot at startup and keep it,
/// so changing any of these needs the pod restarted - flipping <see cref="WorkerCount"/> on a
/// running pod does nothing. That is deliberate rather than lazy: a worker count is a semaphore
/// that has already been sized and a poll interval is a wait already in progress, so re-reading
/// them mid-flight would mean either ignoring the new value or resizing a pool with tasks in it.
/// Kubernetes restarts a pod when its config map changes anyway, which is the same lifecycle the
/// Go service has.
/// </para>
/// </summary>
public sealed class TaskQueueOptions
{
    /// <summary>The configuration section: <c>Tasks</c>.</summary>
    public const string SectionName = "Tasks";

    /// <summary>
    /// How many tasks this pod may run at once, per queue. <b>Zero is the kill switch, and zero is
    /// the shipped default.</b>
    /// <para>
    /// At zero neither the runner nor the reclaim starts at all: no poll, no timer, no connection,
    /// one log line saying so. It is not "start and do nothing" - an operator asking "is this pod
    /// working the queue" gets a straight answer from the log at boot. It is also what makes one
    /// image serve two deployment shapes (decision 02): the same build runs as an API pod at 0 and
    /// as a worker pod at 4, and taking the workers out is a config change rather than a
    /// deployment.
    /// </para>
    /// <para>
    /// Because a zero here must mean zero, the check is inside the runner and the reclaim
    /// themselves. The Go runner instead promotes a non-positive worker count to 1 in its
    /// constructor and leaves the kill switch to one caller remembering to test it first - so a
    /// second queue, or a test that builds a runner straight from config, gets a live worker where
    /// the configuration said none.
    /// </para>
    /// </summary>
    [Range(0, 1024)]
    public int WorkerCount { get; init; }

    /// <summary>
    /// How many attempts a handler should give one task before giving up on it.
    /// <para>
    /// <b>The mechanism does not enforce this and cannot.</b> Neither the re-arm nor the reclaim
    /// counts anything, because only a handler knows whether an attempt made progress - so the
    /// counter lives in the handler's own table or in <c>payload_json</c>, and comparing it against
    /// this number is the handler's job (see <see cref="Application.Ports.Platform.ITaskHandler"/>).
    /// It is configured here rather than per handler so that the budget and the poll cadence that
    /// spends it are read from one section, and the runner logs its effective value at startup -
    /// "how many times will this be retried" is a question an operator asks during an incident, not
    /// one they should have to answer by reading a handler's source.
    /// </para>
    /// </summary>
    [Range(1, 100)]
    public int MaxAttempts { get; init; } = 6;

    /// <summary>
    /// How long to wait before polling again when this pod has no free worker slot, or when the
    /// claim itself failed. Short, because both are conditions that clear on their own.
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:00.010", "00:05:00")]
    public TimeSpan ShortPollInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>
    /// How long to wait before polling again when the queue had nothing due. This is the idle
    /// cost of the mechanism: one <c>SELECT ... FOR UPDATE SKIP LOCKED</c> per queue per interval
    /// per pod, and the floor on how late a task can start after it becomes due.
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:00.010", "01:00:00")]
    public TimeSpan LongPollInterval { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// How long a claim may stand before the reclaim presumes the worker holding it is dead and
    /// releases the row. Zero switches the reclaim off.
    /// <para>
    /// It is also the floor on how long a task lost to a killed pod stays stuck, and the floor on
    /// how slowly a task whose handler threw is retried - so shortening it speeds up recovery and
    /// raises the chance of a second worker starting a task the first one is still working on.
    /// Ten minutes is the Go default.
    /// </para>
    /// <para>
    /// <b>It must stay comfortably above <see cref="TaskTimeout"/>, and the shipped pair is 10
    /// minutes against 5.</b> The gap is the window a cancelled handler has to unwind in before
    /// anybody else may take its row; with no gap, a task that overruns is cancelled and reclaimed
    /// at the same moment, so a handler that does not stop promptly - or does not watch its token
    /// at all, which the mechanism cannot force - runs on while a second worker starts the same
    /// task. Measured, on the real host with this at 4 seconds and no per-task deadline at all:
    /// one row was handed out four times in fifteen seconds - once per timeout plus a reclaim tick
    /// - every copy still running, and those four copies took every worker slot on the pod, after
    /// which nothing else on the queue moved.
    /// </para>
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:00", "1.00:00:00")]
    public TimeSpan StalePoppedTimeout { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// How often the reclaim looks for abandoned claims. Zero switches it off. (Go calls this the
    /// fixer interval.)
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:00", "01:00:00")]
    public TimeSpan ReclaimInterval { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// How long a single task may run before its own cancellation token is cancelled. Zero means
    /// no per-task deadline, which is the Go behaviour.
    /// <para>
    /// This is the token a handler receives, and it is the ONLY thing that cancels it - the host's
    /// shutdown token is never linked to it, so "cancelled" always means "this task overran" and
    /// never "we are going down".
    /// </para>
    /// <para>
    /// <b>It must stay below <see cref="StalePoppedTimeout"/>, and the default is half of it for
    /// that reason.</b> A task allowed to run as long as a claim may stand is a task the reclaim
    /// hands to a second worker while the first is still running - legal, because delivery is
    /// at-least-once, but a permanent double execution rather than a crash-recovery one, and one
    /// that repeats every timeout until the worker pool is full of copies of the same task. Both
    /// values were ten minutes when this port was first written, which is exactly no margin; five
    /// gives a cancelled handler the other five minutes to unwind in. Zero - no deadline at all -
    /// is the shape that produced the four-copies-of-one-row measurement quoted on
    /// <see cref="StalePoppedTimeout"/>, so it is a setting for a queue whose handlers cannot
    /// overrun rather than a default anybody should reach for.
    /// </para>
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:00", "1.00:00:00")]
    public TimeSpan TaskTimeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How long shutdown waits for tasks already in flight, after it has stopped claiming new
    /// ones. Zero means "no bound of our own", leaving <c>HostOptions.ShutdownTimeout</c> as the
    /// only one. The default is the Go service's <c>APP_SHUTDOWN_TIMEOUT</c>.
    /// <para>
    /// It is the queue's own bound rather than the host's on purpose. <c>HostOptions.ShutdownTimeout</c>
    /// (30 seconds by default) bounds the WHOLE shutdown, and the HTTP server's own request drain
    /// is inside it - so lowering that to the Go value would shorten request draining on every
    /// rolling update to buy the queue nothing. Bounding the drain here instead keeps the queue
    /// from eating a budget it shares. Exceeding it is not data loss: the tasks keep running until
    /// the process exits, their rows are still claimed, and the reclaim releases them
    /// <see cref="StalePoppedTimeout"/> later.
    /// </para>
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:00", "00:10:00")]
    public TimeSpan DrainTimeout { get; init; } = TimeSpan.FromSeconds(5);
}
