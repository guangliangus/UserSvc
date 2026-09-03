using System.Collections.Concurrent;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.UnitTests.Tasks;

/// <summary>
/// A <see cref="TimeProvider"/> whose clock only moves when a test moves it, and which says what
/// the code under test is waiting for.
/// <para>
/// It is the seam that makes the runner's timing testable at all. A two-second short poll and a
/// ten-second long poll cannot be told apart by waiting for them - the test would take twelve
/// seconds and still only prove "something happened eventually". Here every
/// <c>Task.Delay(interval, time, token)</c> lands in <see cref="NextDelayAsync"/> as the exact
/// TimeSpan requested, so "an empty claim waits the long interval" is an equality assertion that
/// runs instantly.
/// </para>
/// <para>
/// This is the framework's own abstraction rather than a hand-rolled interface, which is the point:
/// production code waits on <see cref="TimeProvider.System"/> and nothing in it exists to be
/// tested.
/// </para>
/// </summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private readonly object _gate = new();
    private readonly List<ManualTimer> _timers = [];
    private readonly Channel<TimeSpan> _requested = Channel.CreateUnbounded<TimeSpan>();

    private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow()
    {
        lock (_gate)
        {
            return _now;
        }
    }

    /// <summary>Ticks of the virtual clock, so <c>GetElapsedTime</c> follows <see cref="Advance"/>.</summary>
    public override long GetTimestamp() => GetUtcNow().UtcTicks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state);

        lock (_gate)
        {
            _timers.Add(timer);
        }

        timer.Change(dueTime, period);

        return timer;
    }

    /// <summary>
    /// The next wait the code under test asks for. Awaiting it is also how a test knows the loop
    /// has finished an iteration and parked, which is what makes "and then it does NOT poll again"
    /// assertable rather than racy.
    /// </summary>
    public async Task<TimeSpan> NextDelayAsync(CancellationToken cancellationToken = default)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, cancellationToken);

        // A real deadline on the wait, so a runner that never gets to its delay reports as a failed
        // assertion instead of hanging the test run.
        return await _requested.Reader.ReadAsync(linked.Token);
    }

    /// <summary>Moves the clock, firing whatever became due.</summary>
    public void Advance(TimeSpan by)
    {
        List<ManualTimer> due;

        lock (_gate)
        {
            _now += by;
            due = [.. _timers.Where(timer => timer.IsDueAt(_now))];
        }

        // Outside the lock: a callback completes a Task.Delay, whose continuation may create or
        // dispose another timer on this very thread.
        foreach (var timer in due)
        {
            timer.Fire(GetUtcNow());
        }
    }

    private void Requested(TimeSpan dueTime)
    {
        if (dueTime >= TimeSpan.Zero && dueTime != Timeout.InfiniteTimeSpan)
        {
            _requested.Writer.TryWrite(dueTime);
        }
    }

    private void Forget(ManualTimer timer)
    {
        lock (_gate)
        {
            _timers.Remove(timer);
        }
    }

    private sealed class ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state) : ITimer
    {
        private DateTimeOffset? _dueAt;
        private TimeSpan _period = Timeout.InfiniteTimeSpan;

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            _period = period;
            _dueAt = dueTime == Timeout.InfiniteTimeSpan ? null : owner.GetUtcNow() + dueTime;
            owner.Requested(dueTime);

            return true;
        }

        public bool IsDueAt(DateTimeOffset now) => _dueAt is not null && _dueAt <= now;

        public void Fire(DateTimeOffset now)
        {
            if (_dueAt is null || _dueAt > now)
            {
                return;
            }

            _dueAt = _period == Timeout.InfiniteTimeSpan ? null : now + _period;
            callback(state);
        }

        public void Dispose() => owner.Forget(this);

        public ValueTask DisposeAsync()
        {
            Dispose();

            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>
/// An <see cref="ITaskQueue"/> that records what the runner asked of it and answers from a script.
/// <para>
/// The point of a fake rather than a substitute here is the recording: what matters about the
/// runner is the ARGUMENTS it passes - the batch size it computed, the runner id it wrote, the
/// timeout it reclaimed with - and those are properties of the call, not of the answer.
/// </para>
/// </summary>
internal sealed class FakeTaskQueue : ITaskQueue
{
    private readonly ConcurrentQueue<Func<int, IReadOnlyList<QueuedTask>>> _script = new();

    public ConcurrentQueue<(string QueueName, int Limit, string PoppedBy)> PopCalls { get; } = new();

    public ConcurrentQueue<(TimeSpan Timeout, string Actor)> RecoverCalls { get; } = new();

    public ConcurrentQueue<string> CountCalls { get; } = new();

    public int Depth { get; set; }

    /// <summary>Set to throw from the next <see cref="CountPendingAsync"/>.</summary>
    public bool FailCount { get; set; }

    /// <summary>Set to throw from every <see cref="RecoverStaleAsync"/>.</summary>
    public bool FailRecover { get; set; }

    /// <summary>Signalled after each recorded pop, so a test can wait for a poll rather than sleep.</summary>
    public SemaphoreSlim Popped { get; } = new(0);

    /// <summary>Signalled after each recorded reclaim.</summary>
    public SemaphoreSlim Recovered { get; } = new(0);

    /// <summary>Queues one scripted answer. Beyond the script, every pop returns nothing.</summary>
    public FakeTaskQueue Then(Func<int, IReadOnlyList<QueuedTask>> answer)
    {
        _script.Enqueue(answer);

        return this;
    }

    /// <summary>Queues an answer of <paramref name="count"/> tasks, whatever the batch size.</summary>
    public FakeTaskQueue ThenTasks(int count) =>
        Then(_ => [.. Enumerable.Range(1, count).Select(Task)]);

    /// <summary>Queues a failing pop.</summary>
    public FakeTaskQueue ThenThrows() =>
        Then(_ => throw new InvalidOperationException("the claim failed"));

    public static QueuedTask Task(int id) => new(
        id,
        "probe",
        "task-" + id,
        0,
        "{}",
        DateTimeOffset.UnixEpoch,
        DateTimeOffset.UnixEpoch,
        DateTimeOffset.UnixEpoch,
        "runner");

    public Task<int> PushIfNotExistsAsync(
        IReadOnlyCollection<TaskEnqueueRequest> tasks, CancellationToken cancellationToken) =>
        System.Threading.Tasks.Task.FromResult(0);

    public Task<IReadOnlyList<QueuedTask>> PopAsync(
        string queueName, int limit, string poppedBy, CancellationToken cancellationToken)
    {
        PopCalls.Enqueue((queueName, limit, poppedBy));
        Popped.Release();

        return System.Threading.Tasks.Task.FromResult(
            _script.TryDequeue(out var answer) ? answer(limit) : []);
    }

    public Task<bool> DeleteAsync(int id, CancellationToken cancellationToken) =>
        System.Threading.Tasks.Task.FromResult(true);

    public Task<bool> ReArmAsync(int id, TimeSpan delay, string actor, CancellationToken cancellationToken) =>
        System.Threading.Tasks.Task.FromResult(true);

    public Task<int> RecoverStaleAsync(TimeSpan timeout, string actor, CancellationToken cancellationToken)
    {
        RecoverCalls.Enqueue((timeout, actor));
        Recovered.Release();

        if (FailRecover)
        {
            throw new InvalidOperationException("the reclaim failed");
        }

        return System.Threading.Tasks.Task.FromResult(1);
    }

    public Task<int> CountPendingAsync(string queueName, CancellationToken cancellationToken)
    {
        CountCalls.Enqueue(queueName);

        if (FailCount)
        {
            throw new InvalidOperationException("the count failed");
        }

        return System.Threading.Tasks.Task.FromResult(Depth);
    }
}

/// <summary>
/// What the handlers below do, shared so a test can observe every task from one place while the
/// handlers themselves stay one-per-queue scoped types resolved out of the container.
/// </summary>
internal sealed class HandlerProbe
{
    private int _running;

    public ConcurrentQueue<QueuedTask> Handled { get; } = new();

    /// <summary>Handlers wait on this before returning, so a test can hold tasks in flight.</summary>
    public TaskCompletionSource Gate { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Set to make every handler throw.</summary>
    public bool Throw { get; set; }

    /// <summary>Set to make every handler wait on <see cref="Gate"/>.</summary>
    public bool Block { get; set; }

    /// <summary>Set to make every handler wait on its own cancellation token.</summary>
    public bool WaitForCancellation { get; set; }

    /// <summary>The high-water mark of concurrent handlers, which is the concurrency cap under test.</summary>
    public int MaxConcurrent { get; private set; }

    /// <summary>Whether any handler saw its token cancelled.</summary>
    public bool SawCancellation { get; private set; }

    /// <summary>Signalled as each handler starts.</summary>
    public SemaphoreSlim Started { get; } = new(0);

    /// <summary>Signalled as each handler finishes.</summary>
    public SemaphoreSlim Finished { get; } = new(0);

    public async Task HandleAsync(QueuedTask task, CancellationToken cancellationToken)
    {
        Handled.Enqueue(task);

        var running = Interlocked.Increment(ref _running);
        MaxConcurrent = Math.Max(MaxConcurrent, running);
        Started.Release();

        // Registered unconditionally, and that is the point. Observing cancellation only in the
        // mode that waits for it left a hole a mutation walked straight through: handing the
        // handler the host's stopping token instead of its own deadline changed nothing any test
        // could see, because the blocked handler was not watching its token at all. Now every
        // handler notices, whatever it is doing.
        await using var watch = cancellationToken.Register(() => SawCancellation = true);

        try
        {
            if (Throw)
            {
                throw new InvalidOperationException("the handler failed");
            }

            if (WaitForCancellation)
            {
                await System.Threading.Tasks.Task.Delay(Timeout.Infinite, cancellationToken);
            }

            if (Block)
            {
                await Gate.Task;
            }
        }
        finally
        {
            Interlocked.Decrement(ref _running);
            Finished.Release();
        }
    }
}

/// <summary>The handler for queue "probe". Scoped, and resolved per task by the runner.</summary>
internal sealed class ProbeHandler(HandlerProbe probe) : ITaskHandler
{
    public static string QueueName => "probe";

    public Task HandleAsync(QueuedTask task, CancellationToken cancellationToken) =>
        probe.HandleAsync(task, cancellationToken);
}

/// <summary>A second handler for the same queue name as <see cref="ProbeHandler"/>: a wiring bug.</summary>
internal sealed class DuplicateProbeHandler(HandlerProbe probe) : ITaskHandler
{
    public static string QueueName => "probe";

    public Task HandleAsync(QueuedTask task, CancellationToken cancellationToken) =>
        probe.HandleAsync(task, cancellationToken);
}

/// <summary>A handler for a second, unrelated queue.</summary>
internal sealed class OtherHandler(HandlerProbe probe) : ITaskHandler
{
    public static string QueueName => "other";

    public Task HandleAsync(QueuedTask task, CancellationToken cancellationToken) =>
        probe.HandleAsync(task, cancellationToken);
}

/// <summary>
/// An <see cref="IOptions{TOptions}"/> whose <c>Value</c> throws, which is what a real one does
/// when <c>ValidateDataAnnotations</c> rejects the bound section - and, because the section is
/// bound WITHOUT <c>ValidateOnStart</c>, the throw lands at the first read rather than at boot.
/// </summary>
internal sealed class InvalidOptions<T> : IOptions<T> where T : class
{
    public T Value => throw new OptionsValidationException(
        Options.DefaultName, typeof(T), ["ShortPollInterval must be between 00:00:00.010 and 00:05:00."]);
}

/// <summary>
/// An <see cref="ILogger{TCategoryName}"/> that keeps what was written, because for this mechanism
/// the log IS an output. "Is this pod working the queue" has no HTTP endpoint and no metric to
/// answer it: a dormant runner's one Information line is the entire signal, so a test that did not
/// read the log could not tell "off, and said so" from "off, silently".
/// </summary>
internal sealed class RecordingLogger<T> : ILogger<T>
{
    public ConcurrentQueue<(LogLevel Level, string Message, Exception? Error)> Entries { get; } = new();

    public IEnumerable<string> MessagesAt(LogLevel level) =>
        Entries.Where(entry => entry.Level == level).Select(entry => entry.Message);

    public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);

        Entries.Enqueue((logLevel, formatter(state, exception), exception));
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();

        public void Dispose()
        {
        }
    }
}
