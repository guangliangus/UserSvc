using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Ports.Platform;
using UserSvc.Infrastructure.Tasks;
using Xunit;

namespace UserSvc.UnitTests.Tasks;

/// <summary>
/// The runner's own logic, with a fake queue, a fake handler and a clock the test moves.
/// <para>
/// Nothing here waits for a real interval. Every poll delay is requested from a
/// <see cref="ManualTimeProvider"/>, so "an empty claim waits ten seconds" is an equality
/// assertion that returns instantly, and awaiting the next requested delay is also how the test
/// knows the loop has parked - which is what makes the negative assertions ("and then it does NOT
/// poll again") deterministic rather than a race against a sleep.
/// </para>
/// <para>
/// The container is real, and built with <c>validateScopes: true</c>. That is deliberate: the
/// runner is a singleton and <see cref="ITaskQueue"/> is scoped, so a version of it that injected
/// the port directly would throw here exactly as it would at host build.
/// </para>
/// </summary>
public sealed class TaskQueueRunnerTests
{
    private static readonly TimeSpan ShortPoll = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan LongPoll = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The Go original's <c>NewTaskRunner</c> does <c>if cfg.WorkerCount &lt;= 0 { cfg.WorkerCount = 1 }</c>,
    /// so the documented kill switch survives only as long as every caller remembers to test it
    /// before constructing a runner. Here the zero is the runner's own business, and zero means
    /// nothing runs: no poll, no timer, and an <c>ExecuteTask</c> that has already finished.
    /// </summary>
    [Fact]
    public async Task AZeroWorkerCountNeverPollsAndIsNotPromotedToOne()
    {
        var harness = Harness.Build(new TaskQueueOptions { WorkerCount = 0 });

        await harness.Runner.StartAsync(CancellationToken.None);

        await ItReturned(
            harness.Runner,
            "A zero worker count must mean the runner never starts, not that it starts and does "
            + "nothing: there is no loop left to cost anything.");

        harness.Time.Advance(TimeSpan.FromHours(1));
        await Task.Delay(20);

        harness.Queue.PopCalls.ShouldBeEmpty("Nothing may be claimed while the kill switch is on.");
        harness.Queue.CountCalls.ShouldBeEmpty("Not even the depth query: the pod is not in the queue at all.");

        harness.Logger.MessagesAt(LogLevel.Information).ShouldContain(
            message => message.Contains("Task queue runner is off", StringComparison.Ordinal)
                       && message.Contains("WorkerCount", StringComparison.Ordinal),
            "\"Is this pod working the queue\" is the first question asked in an incident and the "
            + "log is the only place that can answer it.");
    }

    /// <summary>
    /// The state this service actually ships in: workers configured, no handler written yet. An
    /// operator who has just set WorkerCount has every reason to think work is being done.
    /// </summary>
    [Fact]
    public async Task NoRegisteredHandlerMeansNothingIsPolledAndTheLogSaysWhy()
    {
        var harness = Harness.Build(new TaskQueueOptions { WorkerCount = 4 }, registerHandler: false);

        await harness.Runner.StartAsync(CancellationToken.None);

        await ItReturned(harness.Runner, "There is nothing to poll, so there is no loop.");
        harness.Queue.PopCalls.ShouldBeEmpty();

        harness.Logger.MessagesAt(LogLevel.Information).ShouldContain(
            message => message.Contains("no handlers registered", StringComparison.Ordinal));
    }

    /// <summary>
    /// The section is bound without <c>ValidateOnStart</c>, so a bad value throws at the first read
    /// of <c>IOptions.Value</c> - which is inside <c>ExecuteAsync</c>. Unhandled, that would stop
    /// the whole host, because <c>BackgroundServiceExceptionBehavior.StopHost</c> is the default:
    /// one wrong interval would take down every HTTP endpoint in the service.
    /// </summary>
    [Fact]
    public async Task AnInvalidTasksSectionBreaksTheQueueAndNothingElse()
    {
        var harness = Harness.Build(new TaskQueueOptions { WorkerCount = 2 }, invalidOptions: true);

        await harness.Runner.StartAsync(CancellationToken.None);

        await ItReturned(
            harness.Runner,
            "An escaping exception here stops the host by default. The queue must fail alone.");

        harness.Logger.MessagesAt(LogLevel.Error).ShouldContain(
            message => message.Contains("Tasks", StringComparison.Ordinal)
                       && message.Contains("invalid", StringComparison.Ordinal),
            "A configuration failure has no HTTP response to carry NOT_CONFIGURED here, so the log "
            + "has to name the section itself.");

        await harness.Runner.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// The two intervals mean different things and the runner must pick per iteration: a failed
    /// claim is transient and comes back at once, an empty queue is the normal idle state and is
    /// the cost of the mechanism at rest.
    /// </summary>
    [Fact]
    public async Task AFailedClaimWaitsTheShortIntervalAndAnEmptyClaimTheLong()
    {
        var harness = Harness.Build(Settings(workers: 2));
        harness.Queue.ThenThrows();

        await harness.Runner.StartAsync(CancellationToken.None);

        (await harness.Time.NextDelayAsync()).ShouldBe(
            ShortPoll, "A claim that failed is retried on the short interval.");

        harness.Time.Advance(ShortPoll);

        (await harness.Time.NextDelayAsync()).ShouldBe(
            LongPoll, "A queue with nothing due is the idle state and waits the long interval.");

        harness.Logger.MessagesAt(LogLevel.Error).ShouldContain(
            message => message.Contains("Failed to claim tasks", StringComparison.Ordinal));

        await harness.Runner.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// The batch size is the free-slot count, exactly. Claiming more than this pod can start would
    /// not queue the extra work locally - it would hide it, because a claimed row is invisible to
    /// every other pod until it is finished or reclaimed.
    /// </summary>
    [Fact]
    public async Task TheBatchSizeIsTheFreeSlotCountAndSlotsComeBackWhenTasksFinish()
    {
        var harness = Harness.Build(Settings(workers: 3));
        harness.Probe.Block = true;
        harness.Queue.ThenTasks(2);

        await harness.Runner.StartAsync(CancellationToken.None);

        await Signalled(harness.Probe.Started);
        await Signalled(harness.Probe.Started);

        // Two of the three slots are held by blocked handlers, so the next claim asks for one.
        (await harness.Time.NextDelayAsync()).ShouldBe(LongPoll);

        harness.Queue.PopCalls.Select(call => call.Limit).ShouldBe(
            [3, 1], "Batch size = free slots, per poll.");

        // Release both handlers; all three slots are free again.
        harness.Probe.Gate.SetResult();
        await Signalled(harness.Probe.Finished);
        await Signalled(harness.Probe.Finished);

        harness.Time.Advance(LongPoll);
        await Signalled(harness.Queue.Popped);

        harness.Queue.PopCalls.Last().Limit.ShouldBe(
            3, "A finished task must give its slot back, or the pool shrinks to nothing.");

        await harness.Runner.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// A saturated pool must not claim rows it cannot start, and must not spin: it waits the short
    /// interval and asks again.
    /// </summary>
    [Fact]
    public async Task WithNoFreeSlotTheRunnerShortPollsWithoutClaiming()
    {
        var harness = Harness.Build(Settings(workers: 1));
        harness.Probe.Block = true;
        harness.Queue.ThenTasks(1);

        await harness.Runner.StartAsync(CancellationToken.None);
        await Signalled(harness.Probe.Started);

        (await harness.Time.NextDelayAsync()).ShouldBe(
            ShortPoll, "No free slot is not an idle queue - it clears as soon as a handler returns.");

        harness.Time.Advance(ShortPoll);
        (await harness.Time.NextDelayAsync()).ShouldBe(ShortPoll);

        harness.Queue.PopCalls.Count.ShouldBe(
            1, "A full pool must issue no claim at all: the statement would take rows away from "
               + "pods that could run them.");

        harness.Probe.Gate.SetResult();
        await harness.Runner.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// One bad task may not stop a queue. The row is deliberately left claimed - the handler owns
    /// the queue row - so the retry is the reclaim's, and the log says so rather than leaving
    /// somebody to work out where the task went.
    /// </summary>
    [Fact]
    public async Task AHandlerThatThrowsDoesNotStopTheLoop()
    {
        var harness = Harness.Build(Settings(workers: 2));
        harness.Probe.Throw = true;
        harness.Queue.ThenTasks(1);

        await harness.Runner.StartAsync(CancellationToken.None);

        await Signalled(harness.Probe.Finished);

        // The loop came back for more after the throw.
        (await harness.Time.NextDelayAsync()).ShouldBe(LongPoll);
        harness.Queue.PopCalls.Count.ShouldBeGreaterThanOrEqualTo(2);

        var errors = harness.Logger.MessagesAt(LogLevel.Error).ToList();
        errors.ShouldContain(
            message => message.Contains("ProbeHandler", StringComparison.Ordinal)
                       && message.Contains("stays claimed", StringComparison.Ordinal),
            "The log has to say the row is still claimed and who will release it, or the task looks lost.");

        harness.Runner.ExecuteTask!.IsCompleted.ShouldBeFalse("The loop must still be running.");

        await harness.Runner.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// Stop means "claim nothing new", not "abandon what is running". The handler's token is never
    /// linked to the host's stopping token, and the drain is what makes the promise real.
    /// </summary>
    [Fact]
    public async Task StopDoesNotInterruptAnInFlightTaskAndTheDrainWaitsForIt()
    {
        var harness = Harness.Build(Settings(workers: 1, drainTimeout: TimeSpan.FromHours(1)));
        harness.Probe.Block = true;
        harness.Queue.ThenTasks(1);

        await harness.Runner.StartAsync(CancellationToken.None);
        await Signalled(harness.Probe.Started);

        var stopping = harness.Runner.StopAsync(CancellationToken.None);
        await Task.Delay(100);

        stopping.IsCompleted.ShouldBeFalse("The drain must still be waiting for the running task.");
        harness.Probe.SawCancellation.ShouldBeFalse(
            "A shutdown must not reach the handler's token: cancelled has to keep meaning \"you "
            + "overran\" and nothing else.");

        harness.Probe.Gate.SetResult();
        await stopping.WaitAsync(TimeSpan.FromSeconds(5));

        harness.Probe.Handled.Count.ShouldBe(1);
        harness.Logger.MessagesAt(LogLevel.Information).ShouldContain(
            message => message.Contains("draining", StringComparison.Ordinal));
    }

    /// <summary>
    /// Two handlers on one queue is a wiring mistake with no safe reading: whichever ran, the
    /// other's work would silently never happen. That queue is refused by name and the rest of the
    /// service's queues keep running.
    /// </summary>
    [Fact]
    public async Task TwoHandlersOnOneQueueRefuseThatQueueAndLeaveTheOthersPolling()
    {
        var harness = Harness.Build(Settings(workers: 1), registerHandler: false, configure: services =>
        {
            services.AddTaskHandler<ProbeHandler>();
            services.AddTaskHandler<DuplicateProbeHandler>();
            services.AddTaskHandler<OtherHandler>();
        });

        await harness.Runner.StartAsync(CancellationToken.None);
        await Signalled(harness.Queue.Popped);

        harness.Queue.PopCalls.Select(call => call.QueueName).Distinct().ShouldBe(["other"]);

        harness.Logger.MessagesAt(LogLevel.Error).ShouldContain(
            message => message.Contains("probe", StringComparison.Ordinal)
                       && message.Contains(nameof(DuplicateProbeHandler), StringComparison.Ordinal));

        await harness.Runner.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// The runner id is written to <c>popped_by</c>, and it is the only thing that ties a stuck row
    /// back to a pod. So it has to name the queue, identify the process, and not change between
    /// polls.
    /// </summary>
    [Fact]
    public async Task TheRunnerIdNamesTheQueueAndIsStableAcrossPolls()
    {
        var harness = Harness.Build(Settings(workers: 1));

        await harness.Runner.StartAsync(CancellationToken.None);
        await harness.Time.NextDelayAsync();
        harness.Time.Advance(LongPoll);
        await Signalled(harness.Queue.Popped);
        await Signalled(harness.Queue.Popped);

        var ids = harness.Queue.PopCalls.Select(call => call.PoppedBy).Distinct().ToList();

        ids.Count.ShouldBe(1, "One runner, one id, for the life of the loop.");
        ids[0].ShouldStartWith("probe-");
        Guid.TryParse(ids[0]["probe-".Length..], out _).ShouldBeTrue(
            "The suffix identifies the process, so it has to be a GUID and not a counter that "
            + "every pod restarts at the same value.");

        await harness.Runner.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// The depth signal lives inside the loop, which is the fix for the Go version's queue-depth
    /// goroutine: that one is launched with no stop channel, so it keeps issuing COUNT(*) after
    /// shutdown has begun - against a closing connection pool - and is the one thing its Stop
    /// cannot account for.
    /// </summary>
    [Fact]
    public async Task TheDepthSignalIsReportedFromTheLoopAndStopsWithIt()
    {
        var harness = Harness.Build(Settings(workers: 1));
        harness.Queue.Depth = 7;

        await harness.Runner.StartAsync(CancellationToken.None);
        await harness.Time.NextDelayAsync();

        harness.Logger.MessagesAt(LogLevel.Information).ShouldContain(
            message => message.Contains("7 task(s) claimable", StringComparison.Ordinal));

        await harness.Runner.StopAsync(CancellationToken.None);
        var afterStop = harness.Queue.CountCalls.Count;

        harness.Time.Advance(TimeSpan.FromHours(1));
        await Task.Delay(50);

        harness.Queue.CountCalls.Count.ShouldBe(
            afterStop, "The depth query must not outlive the loop that owns it.");
    }

    /// <summary>
    /// A depth query that fails is a lost diagnostic, never a lost task - so it must not break the
    /// claim that follows it in the same iteration.
    /// </summary>
    [Fact]
    public async Task AFailedDepthQueryDoesNotStopTheClaim()
    {
        var harness = Harness.Build(Settings(workers: 1));
        harness.Queue.FailCount = true;

        await harness.Runner.StartAsync(CancellationToken.None);
        await Signalled(harness.Queue.Popped);

        harness.Queue.PopCalls.ShouldNotBeEmpty();
        harness.Logger.MessagesAt(LogLevel.Error).ShouldBeEmpty(
            "The claim in the same iteration logs its own error if it fails too; two errors for "
            + "one outage is how a log stops being readable.");

        await harness.Runner.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// The per-task deadline is the one thing that can cancel a handler, and a handler that
    /// overruns must cost its own task and not the loop.
    /// </summary>
    [Fact]
    public async Task ATaskThatOverrunsIsCancelledAndTheLoopKeepsGoing()
    {
        var harness = Harness.Build(Settings(workers: 1, taskTimeout: TimeSpan.FromSeconds(30)));
        harness.Probe.WaitForCancellation = true;
        harness.Queue.ThenTasks(1);

        await harness.Runner.StartAsync(CancellationToken.None);
        await Signalled(harness.Probe.Started);

        harness.Time.Advance(TimeSpan.FromSeconds(30));
        await Signalled(harness.Probe.Finished);

        harness.Probe.SawCancellation.ShouldBeTrue();

        // Waited for rather than asserted outright, and the difference is not cosmetic: the probe
        // releases Finished from its own finally block, which runs while the
        // OperationCanceledException is still unwinding - so the runner's catch has NOT written
        // this line yet when Signalled returns. Asserting it directly failed 2 runs in 28
        // (measured, in a loop); this waits for the effect the test is about instead of for a
        // signal that happens just before it.
        await Logged(
            harness.Logger,
            LogLevel.Warning,
            message => message.Contains("exceeded", StringComparison.Ordinal)
                       && message.Contains("stays claimed", StringComparison.Ordinal),
            "A task cancelled by its own deadline must say so, and say the row is left claimed.");

        harness.Runner.ExecuteTask!.IsCompleted.ShouldBeFalse();

        await harness.Runner.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// The outermost net. An exception escaping a hosted service's <c>ExecuteAsync</c> stops the
    /// whole host - <c>BackgroundServiceExceptionBehavior.StopHost</c> is the default - so a queue
    /// that fails before its loop even starts would take every HTTP endpoint with it. A handler
    /// enumeration that throws is the shape that reaches here: it happens outside every inner
    /// guard, and in a real container it is what a broken registration looks like.
    /// </summary>
    [Fact]
    public async Task AFailureBeforeTheLoopStartsStopsTheQueueAndNotTheHost()
    {
        var harness = Harness.Build(Settings(workers: 1), registrations: new ThrowingRegistrations());

        await harness.Runner.StartAsync(CancellationToken.None);

        await ItReturned(
            harness.Runner,
            "It must return rather than fault: a faulted ExecuteAsync stops the host by default.");

        harness.Logger.MessagesAt(LogLevel.Error).ShouldContain(
            message => message.Contains("stopped unexpectedly", StringComparison.Ordinal));
    }

    /// <summary>Handler registrations that cannot be enumerated, as a broken registration is.</summary>
    private sealed class ThrowingRegistrations : IEnumerable<TaskHandlerRegistration>
    {
        public IEnumerator<TaskHandlerRegistration> GetEnumerator() =>
            throw new InvalidOperationException("the registrations could not be resolved");

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    /// <summary>
    /// The container shape, which is the failure this project has had that no unit test of a type
    /// can catch: both hosted services are singletons and <see cref="ITaskQueue"/> is scoped, so
    /// scope validation is what proves they take <c>IServiceScopeFactory</c> rather than the port.
    /// </summary>
    [Fact]
    public void TheRegisteredWorkersResolveUnderScopeValidation()
    {
        var services = new ServiceCollection();

        services.AddSingleton<ILoggerFactory>(new LoggerFactory());
        services.AddLogging();
        services.AddScoped<ITaskQueue>(_ => new FakeTaskQueue());
        services.AddTaskQueueWorkers(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build());

        using var provider = services.BuildServiceProvider(validateScopes: true);

        var hosted = provider.GetServices<IHostedService>().ToList();

        hosted.Select(service => service.GetType()).ShouldBe(
            [typeof(TaskQueueRunner), typeof(TaskQueueReclaimer)],
            ignoreOrder: true,
            "Both workers must be registered, and resolvable: a scoped port injected into either "
            + "would throw here exactly as it would at host build.");
    }

    /// <summary>
    /// Test settings. <c>TaskTimeout</c> is off unless a test is about it: the per-task deadline is
    /// a timer on the same <see cref="ManualTimeProvider"/>, so leaving it on would put a 10-minute
    /// wait into the recorded waits and the poll-interval assertions would be reading it instead of
    /// the poll. (Measured - that is exactly how they failed first.)
    /// </summary>
    private static TaskQueueOptions Settings(
        int workers, TimeSpan? drainTimeout = null, TimeSpan? taskTimeout = null) => new()
    {
        WorkerCount = workers,
        ShortPollInterval = ShortPoll,
        LongPollInterval = LongPoll,
        DrainTimeout = drainTimeout ?? TimeSpan.FromSeconds(5),
        TaskTimeout = taskTimeout ?? TimeSpan.Zero,
    };

    /// <summary>
    /// Asserts a hosted service's <c>ExecuteAsync</c> has returned, by awaiting it under a deadline.
    /// <para>
    /// Sampling <c>ExecuteTask.IsCompletedSuccessfully</c> right after <c>StartAsync</c> would be
    /// the obvious spelling and it is wrong on .NET 10: measured, <c>StartAsync</c> no longer runs
    /// <c>ExecuteAsync</c> inline - even one whose body is <c>Task.CompletedTask</c> comes back
    /// <c>WaitingForActivation</c> - so the sample races the scheduler rather than reading the
    /// design.
    /// </para>
    /// </summary>
    private static async Task ItReturned(BackgroundService service, string because)
    {
        try
        {
            await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (TimeoutException)
        {
            throw new ShouldAssertException(
                "The hosted service is still running after 5s. " + because);
        }
    }

    /// <summary>
    /// Waits for a signal and fails if it never comes. <c>SemaphoreSlim.WaitAsync(TimeSpan)</c>
    /// returns false on timeout rather than throwing, so an awaited-and-discarded wait turns
    /// "the runner never got there" into a later, much less obvious assertion failure.
    /// </summary>
    private static async Task Signalled(SemaphoreSlim signal) =>
        (await signal.WaitAsync(TimeSpan.FromSeconds(5))).ShouldBeTrue(
            "The runner did not reach this point within 5 seconds.");

    /// <summary>
    /// Waits for a log line, bounded. For the assertions whose subject is written by the runner
    /// AFTER the handler's task has completed - there is no signal for that moment, and the
    /// handler's own signal fires while the exception is still unwinding.
    /// </summary>
    private static async Task Logged(
        RecordingLogger<TaskQueueRunner> logger,
        LogLevel level,
        Func<string, bool> predicate,
        string because)
    {
        ArgumentNullException.ThrowIfNull(predicate);

        for (var attempt = 0; attempt < 500; attempt++)
        {
            if (logger.MessagesAt(level).Any(predicate))
            {
                return;
            }

            await Task.Delay(10);
        }

        throw new ShouldAssertException(
            $"No {level} line matching the expectation was written within 5 seconds. {because}");
    }

    private sealed record Harness(
        TaskQueueRunner Runner,
        FakeTaskQueue Queue,
        HandlerProbe Probe,
        ManualTimeProvider Time,
        RecordingLogger<TaskQueueRunner> Logger)
    {
        public static Harness Build(
            TaskQueueOptions settings,
            bool registerHandler = true,
            bool invalidOptions = false,
            Action<IServiceCollection>? configure = null,
            IEnumerable<TaskHandlerRegistration>? registrations = null)
        {
            var queue = new FakeTaskQueue();
            var probe = new HandlerProbe();
            var time = new ManualTimeProvider();
            var logger = new RecordingLogger<TaskQueueRunner>();

            var services = new ServiceCollection();
            services.AddSingleton(probe);
            services.AddScoped<ITaskQueue>(_ => queue);

            if (registerHandler)
            {
                services.AddTaskHandler<ProbeHandler>();
            }

            configure?.Invoke(services);

            var provider = services.BuildServiceProvider(validateScopes: true);

            IOptions<TaskQueueOptions> options = invalidOptions
                ? new InvalidOptions<TaskQueueOptions>()
                : Options.Create(settings);

            var runner = new TaskQueueRunner(
                provider.GetRequiredService<IServiceScopeFactory>(),
                registrations ?? provider.GetServices<TaskHandlerRegistration>(),
                options,
                time,
                logger);

            return new Harness(runner, queue, probe, time, logger);
        }
    }
}
