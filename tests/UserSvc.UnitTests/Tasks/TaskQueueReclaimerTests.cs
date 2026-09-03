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
/// The reclaim's own logic: when it runs, what it passes, and what it survives.
/// </summary>
public sealed class TaskQueueReclaimerTests
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(10);

    /// <summary>
    /// The same kill switch as the runner, and checked here rather than inherited from a caller.
    /// A pod with no workers is not part of the queue, so it has no business issuing an UPDATE
    /// against a table it never reads.
    /// </summary>
    [Fact]
    public async Task AZeroWorkerCountNeverReclaims()
    {
        var harness = Harness.Build(new TaskQueueOptions { WorkerCount = 0 });

        await harness.Reclaimer.StartAsync(CancellationToken.None);

        await ItReturned(harness.Reclaimer, "A zero worker count starts no reclaim loop.");

        harness.Time.Advance(TimeSpan.FromHours(1));
        await Task.Delay(20);

        harness.Queue.RecoverCalls.ShouldBeEmpty();
        harness.Logger.MessagesAt(LogLevel.Information).ShouldContain(
            message => message.Contains("reclaim is off with the runner", StringComparison.Ordinal));
    }

    /// <summary>
    /// Switching the reclaim off must not slow shutdown down. The Go original gets this wrong: its
    /// Start returns early without closing the channel its WaitDone selects on, so
    /// <c>FCM_SYNC_FIXER_INTERVAL=0</c> adds the whole shutdown timeout to every SIGTERM - five
    /// seconds of a pod that has stopped serving and not yet exited, on every rolling update. Here
    /// the framework owns both halves: a returned <c>ExecuteAsync</c> is an already-completed task,
    /// and StopAsync awaits exactly that.
    /// </summary>
    [Fact]
    public async Task ADisabledReclaimReturnsAtOnceAndCostsShutdownNothing()
    {
        var harness = Harness.Build(Settings(staleAfter: TimeSpan.Zero));

        await harness.Reclaimer.StartAsync(CancellationToken.None);

        await ItReturned(harness.Reclaimer, "A disabled reclaim starts no loop.");

        var stopping = harness.Reclaimer.StopAsync(CancellationToken.None);

        stopping.IsCompleted.ShouldBeTrue(
            "A disabled reclaim has nothing to drain, so stopping it must be instant.");

        await stopping;

        harness.Logger.MessagesAt(LogLevel.Warning).ShouldContain(
            message => message.Contains("reclaim is off", StringComparison.Ordinal)
                       && message.Contains("pin its row", StringComparison.Ordinal),
            "Turning the reclaim off means a killed pod pins work forever - that deserves a "
            + "warning, not silence.");
    }

    /// <summary>
    /// It hands the queue a TimeSpan and an actor: the timeout because the cutoff must be computed
    /// by PostgreSQL rather than by this pod's clock, and the actor because <c>updated_by</c> is
    /// what tells a reader that a row was released by the reclaim and not re-armed by its own
    /// handler.
    /// </summary>
    [Fact]
    public async Task ItReclaimsWithTheConfiguredTimeoutAndAnActorNamingTheReclaim()
    {
        var harness = Harness.Build(Settings());

        await harness.Reclaimer.StartAsync(CancellationToken.None);
        await Signalled(harness.Queue.Recovered);

        var call = harness.Queue.RecoverCalls.Single();

        call.Timeout.ShouldBe(StaleAfter);
        call.Actor.ShouldStartWith("task-queue-reclaimer-");
        Guid.TryParse(call.Actor["task-queue-reclaimer-".Length..], out _).ShouldBeTrue();

        harness.Logger.MessagesAt(LogLevel.Warning).ShouldContain(
            message => message.Contains("released 1 claim(s)", StringComparison.Ordinal),
            "Zero is the healthy value, so anything above it is a warning: that many workers died "
            + "holding work.");

        await harness.Reclaimer.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// A reclaim that fails delays recovery; a reclaim that stops means no abandoned claim on this
    /// pod is ever released again.
    /// </summary>
    [Fact]
    public async Task AFailedReclaimDoesNotStopTheTimer()
    {
        var harness = Harness.Build(Settings());
        harness.Queue.FailRecover = true;

        await harness.Reclaimer.StartAsync(CancellationToken.None);
        await Signalled(harness.Queue.Recovered);

        (await harness.Time.NextDelayAsync()).ShouldBe(
            Interval, "The interval is the gap between runs, so a slow UPDATE cannot queue ticks up behind it.");

        harness.Time.Advance(Interval);
        await Signalled(harness.Queue.Recovered);

        harness.Queue.RecoverCalls.Count.ShouldBeGreaterThanOrEqualTo(2);
        harness.Queue.RecoverCalls.Select(call => call.Actor).Distinct().Count().ShouldBe(
            1, "One reclaimer, one id, for the life of the loop.");

        harness.Logger.MessagesAt(LogLevel.Error).ShouldContain(
            message => message.Contains("retrying on the next tick", StringComparison.Ordinal));

        harness.Reclaimer.ExecuteTask!.IsCompleted.ShouldBeFalse();

        await harness.Reclaimer.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// As in the runner: without <c>ValidateOnStart</c> the throw lands at the first read, and
    /// unhandled it would stop the host rather than the reclaim.
    /// </summary>
    [Fact]
    public async Task AnInvalidTasksSectionBreaksTheReclaimAndNothingElse()
    {
        var harness = Harness.Build(Settings(), invalidOptions: true);

        await harness.Reclaimer.StartAsync(CancellationToken.None);

        await ItReturned(harness.Reclaimer, "An invalid section starts no loop.");
        harness.Queue.RecoverCalls.ShouldBeEmpty();

        harness.Logger.MessagesAt(LogLevel.Error).ShouldContain(
            message => message.Contains("Tasks", StringComparison.Ordinal));

        await harness.Reclaimer.StopAsync(CancellationToken.None);
    }

    /// <summary>See the note on the runner tests' equivalent: awaiting the task is the only honest
    /// way to assert a hosted service returned, because .NET 10's StartAsync does not run
    /// ExecuteAsync inline.</summary>
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

    private static async Task Signalled(SemaphoreSlim signal) =>
        (await signal.WaitAsync(TimeSpan.FromSeconds(5))).ShouldBeTrue(
            "The reclaim did not reach this point within 5 seconds.");

    private static TaskQueueOptions Settings(TimeSpan? staleAfter = null) => new()
    {
        WorkerCount = 1,
        StalePoppedTimeout = staleAfter ?? StaleAfter,
        ReclaimInterval = Interval,
    };

    private sealed record Harness(
        TaskQueueReclaimer Reclaimer,
        FakeTaskQueue Queue,
        ManualTimeProvider Time,
        RecordingLogger<TaskQueueReclaimer> Logger)
    {
        public static Harness Build(TaskQueueOptions settings, bool invalidOptions = false)
        {
            var queue = new FakeTaskQueue();
            var time = new ManualTimeProvider();
            var logger = new RecordingLogger<TaskQueueReclaimer>();

            var services = new ServiceCollection();
            services.AddScoped<ITaskQueue>(_ => queue);

            var provider = services.BuildServiceProvider(validateScopes: true);

            IOptions<TaskQueueOptions> options = invalidOptions
                ? new InvalidOptions<TaskQueueOptions>()
                : Options.Create(settings);

            var reclaimer = new TaskQueueReclaimer(
                provider.GetRequiredService<IServiceScopeFactory>(), options, time, logger);

            return new Harness(reclaimer, queue, time, logger);
        }
    }
}
