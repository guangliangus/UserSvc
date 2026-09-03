using Microsoft.EntityFrameworkCore;
using Shouldly;
using UserSvc.Application.Ports.Platform;
using UserSvc.Infrastructure.Persistence;
using UserSvc.Infrastructure.Persistence.Repositories;
using Xunit;

namespace UserSvc.UnitTests.Tasks;

/// <summary>
/// The adapter's own logic: what it refuses, and what it answers without asking the database.
/// <para>
/// The context here points at a port nothing is listening on, which is the assertion. Every test
/// below claims "this needs no round trip" - a batch of no tasks, a batch of no worker slots, a
/// reclaim that is switched off, an argument that is wrong - and a connection attempt would take
/// the better part of a second and then throw, so the claim is checked rather than described.
/// </para>
/// </summary>
public sealed class TaskQueueRepositoryTests
{
    private static (UserSvcDbContext Db, ITaskQueue Queue) Unreachable()
    {
        var db = new UserSvcDbContext(new DbContextOptionsBuilder<UserSvcDbContext>()
            .UseNpgsql("Host=127.0.0.1;Port=1;Database=none;Username=none;Password=none")
            .UseSnakeCaseNamingConvention()
            .Options);

        return (db, new TaskQueueRepository(db));
    }

    [Fact]
    public async Task EnqueueingNothingIsASuccessfulNoOpAndCostsNoRoundTrip()
    {
        var (db, queue) = Unreachable();
        await using var owned = db;

        var pushed = await queue.PushIfNotExistsAsync([], CancellationToken.None);

        pushed.ShouldBe(
            0,
            "A producer that reconciles a set is entitled to find the set empty; that is not an "
            + "error, and it must not become a statement.");
    }

    [Fact]
    public async Task ClaimingWithNoFreeWorkerSlotsReturnsNothingAndCostsNoRoundTrip()
    {
        var (db, queue) = Unreachable();
        await using var owned = db;

        (await queue.PopAsync("q", 0, "runner", CancellationToken.None)).ShouldBeEmpty(
            "The runner's batch size is its count of free worker slots, and having none is the "
            + "normal state of a busy pool - so this is the hot path, not an edge case. LIMIT 0 "
            + "would still cost a round trip and LIMIT -1 is a syntax error.");

        (await queue.PopAsync("q", -1, "runner", CancellationToken.None)).ShouldBeEmpty();
    }

    /// <summary>
    /// Zero is the reclaim's off switch, and the check is deliberately outside the statement: a
    /// zero cutoff in the WHERE clause would reclaim every row the instant it was claimed, taking
    /// work away from the workers currently doing it. "Disabled" must not mean "maximally
    /// aggressive".
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task AStaleReclaimWithNoTimeoutIsSwitchedOffRatherThanImmediate(int seconds)
    {
        var (db, queue) = Unreachable();
        await using var owned = db;

        var recovered = await queue.RecoverStaleAsync(
            TimeSpan.FromSeconds(seconds), "fixer", CancellationToken.None);

        recovered.ShouldBe(0);
    }

    /// <summary>
    /// A blank queue name satisfies every constraint on the table, so the database would accept the
    /// row and no runner would ever poll it: a task that silently never runs. Refused at the edge
    /// instead.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ATaskWithNoQueueNameIsRefusedBeforeItCanBecomeARowNobodyPolls(string queueName)
    {
        var (db, queue) = Unreachable();
        await using var owned = db;

        await Should.ThrowAsync<ArgumentException>(async () =>
            await queue.PushIfNotExistsAsync(
                [new TaskEnqueueRequest(queueName, "task-1")], CancellationToken.None));
    }

    /// <summary>
    /// The task id is the whole idempotency story: without one, "at most one row per unit of work"
    /// degrades to "at most one row with a blank id", and every producer of that queue collides
    /// with every other.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public async Task ATaskWithNoIdempotencyKeyIsRefused(string taskId)
    {
        var (db, queue) = Unreachable();
        await using var owned = db;

        await Should.ThrowAsync<ArgumentException>(async () =>
            await queue.PushIfNotExistsAsync(
                [new TaskEnqueueRequest("q", taskId)], CancellationToken.None));
    }

    /// <summary>
    /// A negative priority is refused here rather than by <c>chk_task_queues_priority</c>. The
    /// CHECK is the right backstop for a hand-written INSERT, but as the only guard it reports the
    /// caller's mistake as SQLSTATE 23514 two layers away from the caller.
    /// </summary>
    [Fact]
    public async Task ANegativePriorityIsRefusedByTheAdapterAndNotOnlyByTheCheckConstraint()
    {
        var (db, queue) = Unreachable();
        await using var owned = db;

        await Should.ThrowAsync<ArgumentOutOfRangeException>(async () =>
            await queue.PushIfNotExistsAsync(
                [new TaskEnqueueRequest("q", "task-1", Priority: -1)], CancellationToken.None));
    }

    /// <summary>
    /// One bad task in a batch stops the whole batch, before any statement is issued. The
    /// alternative - enqueue the good ones and report the bad one - would make a partial enqueue
    /// the caller's problem to unpick, and the batch is one statement precisely so that it cannot
    /// half-apply.
    /// </summary>
    [Fact]
    public async Task OneInvalidTaskRefusesTheWholeBatchRatherThanEnqueueingTheRest()
    {
        var (db, queue) = Unreachable();
        await using var owned = db;

        await Should.ThrowAsync<ArgumentException>(async () =>
            await queue.PushIfNotExistsAsync(
                [
                    new TaskEnqueueRequest("q", "good-1"),
                    new TaskEnqueueRequest("q", ""),
                ],
                CancellationToken.None));
    }

    [Fact]
    public async Task ClaimingFromAQueueWithNoNameIsRefused()
    {
        var (db, queue) = Unreachable();
        await using var owned = db;

        await Should.ThrowAsync<ArgumentException>(async () =>
            await queue.PopAsync(" ", 1, "runner", CancellationToken.None));

        await Should.ThrowAsync<ArgumentException>(async () =>
            await queue.CountPendingAsync("", CancellationToken.None));
    }

    /// <summary>
    /// The default enqueue request is the shape almost every producer will use: a queue, a key, no
    /// payload, no delay, lowest priority. Asserted so a later parameter reorder or default change
    /// cannot alter what "just enqueue this" means without failing here.
    /// </summary>
    [Fact]
    public void TheDefaultEnqueueRequestIsAnImmediateLowestPriorityEmptyPayloadTask()
    {
        var request = new TaskEnqueueRequest("fcm_topic_sync", "installation-7");

        request.PayloadJson.ShouldBe("{}");
        request.Priority.ShouldBe(0);
        request.Delay.ShouldBeNull("Null is \"as soon as possible\", recorded as the database's own now().");
        request.Actor.ShouldBe(string.Empty);
    }
}
