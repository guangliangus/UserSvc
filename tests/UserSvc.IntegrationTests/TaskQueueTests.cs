using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Shouldly;
using UserSvc.Application.Ports.Platform;
using UserSvc.IntegrationTests.Infrastructure;

namespace UserSvc.IntegrationTests;

/// <summary>
/// The task queue against a real PostgreSQL, because every property worth asserting about it is a
/// property of the database: <c>FOR UPDATE SKIP LOCKED</c>, <c>ON CONFLICT DO NOTHING</c>, a
/// server-side <c>now()</c>, and a partial index. A fake store answers all of them the wrong way
/// and never fails.
/// <para>
/// The mechanism ships dormant - the runner's worker count is zero by default and this service has
/// no production handler yet - so these tests are the only thing that exercises the six operations
/// at all. That is stated rather than hidden: what makes them worth their runtime is that they
/// drive the SQL a runner will drive later, not that something in the service calls them today.
/// </para>
/// </summary>
public sealed class TaskQueueTests(ServiceFixture fixture) : IntegrationTest(fixture)
{
    private const string Queue = "test_queue";

    private const string OtherQueue = "other_queue";

    /// <summary>
    /// The claim is atomic under real contention. Four pollers, two hundred rows, fifty each: with
    /// the claim split into a select and a separate update, two of them would see the same
    /// unclaimed rows before either wrote, and the union below would be short of two hundred
    /// distinct ids.
    /// <para>
    /// The batch size and the row count are chosen so the expected result does not depend on
    /// timing: whoever goes first takes fifty of the two hundred, so every poller finds fifty
    /// waiting whatever order they arrive in.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task FourConcurrentPollersClaimTwoHundredRowsWithNoRowGoingToTwoOfThem()
    {
        await EnqueueAsync(Enumerable.Range(1, 200).Select(Seed).ToArray());

        var claims = await Task.WhenAll(
            Enumerable.Range(1, 4).Select(async runner =>
            {
                await using var scope = Fixture.CreateScope();
                var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();
                return await queue.PopAsync(
                    Queue, 50, $"runner-{runner}", CancellationToken.None);
            }));

        foreach (var claim in claims)
        {
            claim.Count.ShouldBe(
                50,
                "Every poller asked for fifty and there were always at least fifty unclaimed rows "
                + "left, so a short batch means rows were lost to a race rather than shared out.");
        }

        var ids = claims.SelectMany(claim => claim.Select(task => task.Id)).ToArray();

        ids.Length.ShouldBe(200);
        ids.Distinct().Count().ShouldBe(
            200,
            "A row handed to two workers is the failure this queue exists to prevent: both would "
            + "run the side effect and both would then write the outcome.");

        (await Fixture.CountAsync(
                "SELECT count(*) FROM identity.task_queues WHERE queue_name = @p0 AND popped = true",
                Queue))
            .ShouldBe(200, "Claiming and marking claimed are the same statement.");
    }

    /// <summary>
    /// <c>SKIP LOCKED</c>, pinned precisely. The first poller holds its transaction open, so its
    /// rows are locked and its claim is invisible to anybody else; a second poller must step over
    /// them and take different rows.
    /// <para>
    /// Without <c>SKIP LOCKED</c> the second poller <b>blocks</b> on the first one's row locks -
    /// which is why it is given a deadline here. A hung test reports nothing useful; a cancelled
    /// query reports exactly what broke.
    /// </para>
    /// <para>
    /// The transaction is opened through <see cref="IUnitOfWork.ExecuteInTransactionAsync"/> and
    /// not <c>BeginTransactionAsync</c>, and that is a constraint rather than a style choice: this
    /// context is built with <c>EnableRetryOnFailure</c>, so a LINQ query - <c>Pop</c> included -
    /// inside a hand-opened transaction throws "the configured execution strategy
    /// 'NpgsqlRetryingExecutionStrategy' does not support user-initiated transactions". Measured
    /// here before this test was rewritten.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task ASecondPollerStepsOverRowsAHeldTransactionHasLockedInsteadOfWaitingForThem()
    {
        await EnqueueAsync([Seed(1), Seed(2), Seed(3), Seed(4)]);

        IReadOnlyList<QueuedTask> held = [];
        IReadOnlyList<QueuedTask> stepped = [];
        var blocked = false;

        await using var holder = Fixture.CreateScope();
        var holderQueue = holder.ServiceProvider.GetRequiredService<ITaskQueue>();
        var holderUnitOfWork = holder.ServiceProvider.GetRequiredService<IUnitOfWork>();

        await holderUnitOfWork.ExecuteInTransactionAsync(async token =>
        {
            held = await holderQueue.PopAsync(Queue, 2, "runner-holder", token);

            // A second poller on its own scope, and therefore its own connection, while the first
            // one's transaction is still open and its claim still uncommitted.
            await using var second = Fixture.CreateScope();
            var secondQueue = second.ServiceProvider.GetRequiredService<ITaskQueue>();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            try
            {
                stepped = await secondQueue.PopAsync(Queue, 4, "runner-second", deadline.Token);
            }
            catch (Exception exception) when (exception is OperationCanceledException or PostgresException)
            {
                blocked = true;
            }
        }, CancellationToken.None);

        held.Count.ShouldBe(2);

        blocked.ShouldBeFalse(
            "The second poller waited for the first one's locks. Without SKIP LOCKED every pod "
            + "polling a queue serialises behind whichever pod got there first, which is the whole "
            + "reason the claim is written this way.");

        stepped.Count.ShouldBe(
            2, "Two of the four rows were locked, so the other two were available.");

        stepped.Select(task => task.Id).Intersect(held.Select(task => task.Id)).ShouldBeEmpty(
            "The locked rows were still popped = false in the second poller's snapshot - the first "
            + "poller had not committed - so only the row lock kept them apart.");

        (await Fixture.CountAsync(
                "SELECT count(*) FROM identity.task_queues WHERE popped = true"))
            .ShouldBe(4, "The holder's transaction committed, so all four claims stand.");
    }

    /// <summary>
    /// The unconditional enqueue. Every producer pushes without checking, and the unique index
    /// decides - so the second push is a success that inserted nothing, not a conflict the producer
    /// has to handle.
    /// </summary>
    [RequiresDockerFact]
    public async Task EnqueueingTheSameTaskTwiceLeavesOneRowAndReportsThatNothingWasInserted()
    {
        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        var first = await queue.PushIfNotExistsAsync(
            [new TaskEnqueueRequest(Queue, "same", """{"attempt":1}""", 3, null, "producer-a")],
            CancellationToken.None);

        var second = await queue.PushIfNotExistsAsync(
            [new TaskEnqueueRequest(Queue, "same", """{"attempt":2}""", 9, null, "producer-b")],
            CancellationToken.None);

        first.ShouldBe(1);
        second.ShouldBe(
            0,
            "Zero inserted is the success case for a duplicate. If this threw, the producer's "
            + "business write would roll back with it.");

        (await Fixture.QueryStringsAsync(
                "SELECT payload_json::text FROM identity.task_queues WHERE task_id = 'same'"))
            .ShouldBe(
                ["""{"attempt": 1}"""],
                "The first writer wins outright - the second push must not update the row it "
                + "found, or a retry would reset whatever the first producer scheduled.");

        (await Fixture.QueryStringsAsync(
                "SELECT created_by FROM identity.task_queues WHERE task_id = 'same'"))
            .ShouldBe(["producer-a"]);
    }

    /// <summary>
    /// A queue is only its own. The unique slot is (queue_name, task_id), so the same task id in
    /// two queues is two units of work - which is what lets one subject be reconciled by two
    /// independent capabilities.
    /// </summary>
    [RequiresDockerFact]
    public async Task TheSameTaskIdInADifferentQueueIsADifferentUnitOfWork()
    {
        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        var pushed = await queue.PushIfNotExistsAsync(
            [
                new TaskEnqueueRequest(Queue, "shared"),
                new TaskEnqueueRequest(OtherQueue, "shared"),
            ],
            CancellationToken.None);

        pushed.ShouldBe(2);

        (await queue.PopAsync(Queue, 10, "runner", CancellationToken.None))
            .Select(task => task.QueueName)
            .ShouldBe([Queue], "A poller claims from its own queue and never from another.");

        (await queue.CountPendingAsync(OtherQueue, CancellationToken.None)).ShouldBe(1);
    }

    /// <summary>
    /// Claim order is priority first, then the oldest delivery time, then the oldest row - the
    /// order the claim index is built in. The assertion is on the order the port hands the tasks
    /// over in, because <c>UPDATE ... RETURNING</c> promises nothing about the order it emits.
    /// </summary>
    [RequiresDockerFact]
    public async Task TasksAreClaimedByPriorityThenByHowLongTheyHaveBeenDue()
    {
        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        // Enqueued lowest priority first, so insertion order is the opposite of claim order and
        // cannot be mistaken for it. The negative delays make two rows due earlier than the rest.
        await queue.PushIfNotExistsAsync(
            [
                new TaskEnqueueRequest(Queue, "low", Priority: 0),
                new TaskEnqueueRequest(Queue, "high-recent", Priority: 9),
                new TaskEnqueueRequest(Queue, "middle", Priority: 5),
                new TaskEnqueueRequest(Queue, "high-overdue", Priority: 9, Delay: TimeSpan.FromMinutes(-30)),
            ],
            CancellationToken.None);

        var claimed = await queue.PopAsync(Queue, 10, "runner", CancellationToken.None);

        claimed.Select(task => task.TaskId).ShouldBe(
            ["high-overdue", "high-recent", "middle", "low"],
            "Priority outranks age, and among equal priorities the one that has been due longest "
            + "goes first.");
    }

    /// <summary>
    /// A delay is honoured on the database's clock, and a task waiting on one is neither claimable
    /// nor counted as backlog. Counting it would make a healthy queue with slow retries look
    /// identical to a stalled one.
    /// </summary>
    [RequiresDockerFact]
    public async Task ADelayedTaskIsNeitherClaimableNorCountedAsBacklogUntilItIsDue()
    {
        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        await queue.PushIfNotExistsAsync(
            [
                new TaskEnqueueRequest(Queue, "now"),
                new TaskEnqueueRequest(Queue, "later", Delay: TimeSpan.FromHours(1)),
            ],
            CancellationToken.None);

        (await queue.CountPendingAsync(Queue, CancellationToken.None)).ShouldBe(1);

        (await queue.PopAsync(Queue, 10, "runner", CancellationToken.None))
            .Select(task => task.TaskId)
            .ShouldBe(["now"]);

        (await Fixture.CountAsync(
                "SELECT count(*) FROM identity.task_queues WHERE task_id = 'later' AND deliver_on > now()"))
            .ShouldBe(1, "deliver_on is now() + delay computed by PostgreSQL, not by this process.");
    }

    /// <summary>
    /// Re-arming releases the claim as well as moving the delivery time. The released row must be
    /// claimable cleanly by whoever picks it up next, and until it is due it must not be claimable
    /// at all.
    /// </summary>
    [RequiresDockerFact]
    public async Task ReArmingReleasesTheWholeClaimAndHoldsTheRowBackUntilItIsDueAgain()
    {
        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        await EnqueueAsync([Seed(1)]);
        var claimed = await queue.PopAsync(Queue, 1, "runner-a", CancellationToken.None);
        var id = claimed.Single().Id;

        (await queue.ReArmAsync(id, TimeSpan.FromMinutes(5), "runner-a", CancellationToken.None))
            .ShouldBeTrue();

        (await Fixture.QueryStringsAsync(
                """
                SELECT popped::text || '|' || coalesce(popped_at::text, 'null') || '|' ||
                       popped_by || '|' || (deliver_on > now())::text || '|' || updated_by
                FROM identity.task_queues WHERE id = @p0
                """,
                id))
            .ShouldBe(
                // popped_by is the empty segment between the two pipes.
                ["false|null||true|runner-a"],
                "popped_by is cleared with the flag: it must name whoever holds the row, not "
                + "whoever last gave it up, or it is worthless on a stuck row.");

        (await queue.PopAsync(Queue, 10, "runner-b", CancellationToken.None)).ShouldBeEmpty(
            "The backoff is the delivery time, so a re-armed row is invisible to every poller "
            + "until it comes due.");

        (await queue.ReArmAsync(id, TimeSpan.Zero, "runner-a", CancellationToken.None))
            .ShouldBeTrue();

        (await queue.PopAsync(Queue, 10, "runner-b", CancellationToken.None))
            .Select(task => task.PoppedBy)
            .ShouldBe(["runner-b"]);

        (await queue.ReArmAsync(int.MaxValue, TimeSpan.Zero, "runner-a", CancellationToken.None))
            .ShouldBeFalse("A row that no longer exists cannot be released, and saying so is not an error.");
    }

    /// <summary>
    /// The terminal delete, and what a duplicate delivery of a finished task looks like. It also
    /// frees the (queue, task id) slot, which is the reason the row is removed rather than marked -
    /// the same subject has to be enqueueable again.
    /// </summary>
    [RequiresDockerFact]
    public async Task DeletingATaskFreesItsSlotForTheNextTimeTheSameWorkIsNeeded()
    {
        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        await queue.PushIfNotExistsAsync(
            [new TaskEnqueueRequest(Queue, "recurring")], CancellationToken.None);

        var id = (await queue.PopAsync(Queue, 1, "runner", CancellationToken.None)).Single().Id;

        (await queue.DeleteAsync(id, CancellationToken.None)).ShouldBeTrue();
        (await queue.DeleteAsync(id, CancellationToken.None)).ShouldBeFalse(
            "Already gone is what an at-least-once redelivery of a finished task sees, so it is a "
            + "false rather than a throw.");

        (await queue.PushIfNotExistsAsync(
                [new TaskEnqueueRequest(Queue, "recurring")], CancellationToken.None))
            .ShouldBe(
                1,
                "A terminal row left behind would refuse every future reconcile of the same "
                + "subject - the queue would accept each task once for the life of the database.");
    }

    /// <summary>
    /// The stale-claim reclaim: a pod that died holding work must not pin it forever, and a pod
    /// that is merely still working must not have it taken away.
    /// </summary>
    [RequiresDockerFact]
    public async Task OnlyClaimsOlderThanTheTimeoutAreReclaimedAndUnclaimedRowsAreLeftAlone()
    {
        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        await EnqueueAsync([Seed(1), Seed(2), Seed(3)]);
        var claimed = await queue.PopAsync(Queue, 2, "runner-crashed", CancellationToken.None);

        // Backdate one claim by twenty minutes to stand in for the pod that died holding it. The
        // clock is the database's on both sides of the comparison, so no test clock is involved.
        await Fixture.ExecuteAsync(
            "UPDATE identity.task_queues SET popped_at = now() - interval '20 minutes' WHERE id = @p0",
            claimed[0].Id);

        var recovered = await queue.RecoverStaleAsync(
            TimeSpan.FromMinutes(10), "fixer-1", CancellationToken.None);

        recovered.ShouldBe(
            1,
            "One claim was twenty minutes old and one was seconds old; a reclaim that took both "
            + "would be taking work off a worker that is still doing it.");

        (await Fixture.QueryStringsAsync(
                """
                SELECT task_id FROM identity.task_queues
                WHERE popped = false ORDER BY task_id
                """))
            .ShouldBe([Seed(1).TaskId, Seed(3).TaskId]);

        (await Fixture.QueryStringsAsync(
                "SELECT updated_by FROM identity.task_queues WHERE id = @p0", claimed[0].Id))
            .ShouldBe(
                ["fixer-1"],
                "A reclaim has to be distinguishable from a handler's own re-arm when somebody "
                + "reads the table asking what happened.");

        (await queue.PopAsync(Queue, 10, "runner-fresh", CancellationToken.None))
            .Select(task => task.TaskId)
            .ShouldBe(
                [Seed(1).TaskId, Seed(3).TaskId],
                "A reclaimed row is claimable at once - it was already due before it was claimed - "
                + "and it keeps its place in the claim order. Both rows were enqueued by one "
                + "statement so they share a deliver_on, and the tiebreak is the id: the recovered "
                + "row goes first because it is older. Stamping deliver_on with now() on reclaim, "
                + "which the Go original does, would put it second - behind work that arrived "
                + "while it was stuck.");
    }

    /// <summary>
    /// The whole point of the reclaim being harmless: it is safe to run on a schedule against a
    /// queue where nothing is wrong.
    /// </summary>
    [RequiresDockerFact]
    public async Task AReclaimFindsNothingWhenEveryClaimIsFresh()
    {
        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        await EnqueueAsync([Seed(1), Seed(2)]);
        await queue.PopAsync(Queue, 2, "runner", CancellationToken.None);

        (await queue.RecoverStaleAsync(TimeSpan.FromMinutes(10), "fixer", CancellationToken.None))
            .ShouldBe(0);

        (await Fixture.CountAsync("SELECT count(*) FROM identity.task_queues WHERE popped = true"))
            .ShouldBe(2);
    }

    /// <summary>
    /// A payload is stored as <c>jsonb</c>, so the database is what validates it. An unspecified
    /// payload becomes an empty object rather than reaching the cast as an empty string, and
    /// malformed JSON is refused by PostgreSQL rather than stored and discovered by the handler.
    /// </summary>
    [RequiresDockerFact]
    public async Task AnUnspecifiedPayloadIsStoredAsAnEmptyObjectAndMalformedJsonIsRefused()
    {
        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        await queue.PushIfNotExistsAsync(
            [
                new TaskEnqueueRequest(Queue, "blank", string.Empty),
                new TaskEnqueueRequest(Queue, "spaces", "   "),
            ],
            CancellationToken.None);

        (await Fixture.QueryStringsAsync(
                "SELECT payload_json::text FROM identity.task_queues ORDER BY task_id"))
            .ShouldBe(["{}", "{}"]);

        var refused = await Should.ThrowAsync<PostgresException>(async () =>
            await queue.PushIfNotExistsAsync(
                [new TaskEnqueueRequest(Queue, "broken", "not json")], CancellationToken.None));

        refused.SqlState.ShouldBe(
            "22P02",
            "A producer sending malformed JSON has a bug the database should report, not one this "
            + "adapter should paper over by storing text nobody can read back.");
    }

    /// <summary>
    /// The audit columns are NOT NULL on this table - the one shape change this port deliberately
    /// makes to the Go original, whose created_by / updated_by were nullable TEXT. A producer that
    /// names no actor gets the empty string, which is this project's shape, and never a NULL.
    /// </summary>
    [RequiresDockerFact]
    public async Task AProducerThatNamesNoActorGetsAnEmptyAuditStampRatherThanANull()
    {
        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        await queue.PushIfNotExistsAsync(
            [new TaskEnqueueRequest(Queue, "anonymous")], CancellationToken.None);

        (await Fixture.CountAsync(
                """
                SELECT count(*) FROM identity.task_queues
                WHERE created_by = '' AND updated_by = '' AND popped_by = ''
                """))
            .ShouldBe(1);

        (await Fixture.CountAsync(
                """
                SELECT count(*) FROM identity.task_queues
                WHERE created_by IS NULL OR updated_by IS NULL OR popped_by IS NULL
                """))
            .ShouldBe(0);
    }

    /// <summary>
    /// The enqueue runs on the caller's connection and therefore inside the caller's transaction.
    /// That is the guarantee a producer relies on: the row that causes the work and the row that
    /// records the work commit together, or neither does.
    /// </summary>
    [RequiresDockerFact]
    public async Task AnEnqueueRolledBackWithItsCallersTransactionLeavesNoTaskBehind()
    {
        await using (var scope = Fixture.CreateScope())
        {
            var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();
            var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();

            // Shaped like a real producer: enqueue the work, then have the step after it fail. The
            // transaction is opened by the unit of work, which is what this service's callers use
            // and the only form the retrying execution strategy accepts.
            await Should.ThrowAsync<InvalidOperationException>(async () =>
                await unitOfWork.ExecuteInTransactionAsync(
                    async token =>
                    {
                        await queue.PushIfNotExistsAsync(
                            [new TaskEnqueueRequest(Queue, "doomed")], token);

                        throw new InvalidOperationException("the business step after the enqueue failed");
                    },
                    CancellationToken.None));
        }

        (await Fixture.CountAsync("SELECT count(*) FROM identity.task_queues")).ShouldBe(
            0,
            "An enqueue that survived its caller's rollback would schedule work for a change that "
            + "never happened - the mirror image of the outbox's guarantee.");
    }

    /// <summary>
    /// The whole shape a handler will have: claim, do the domain write, finish the task, one
    /// transaction. It is asserted because every operation this port offers is issued immediately
    /// rather than batched into SaveChanges, so "it runs inside the caller's transaction" is a
    /// claim about the connection rather than something the type system enforces.
    /// <para>
    /// It also pins the seam a handler has to use. <c>Pop</c> and <c>Delete</c> are LINQ, so they
    /// go through the retrying execution strategy and refuse to run in a transaction the caller
    /// opened by hand; opened through the unit of work - inside the strategy - they are fine.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task ClaimingAndFinishingATaskInsideOneUnitOfWorkTransactionCommitsTogether()
    {
        await EnqueueAsync([Seed(1)]);

        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();

        var finished = false;

        await unitOfWork.ExecuteInTransactionAsync(async token =>
        {
            var claimed = await queue.PopAsync(Queue, 1, "runner", token);
            claimed.Count.ShouldBe(1);

            finished = await queue.DeleteAsync(claimed[0].Id, token);
        }, CancellationToken.None);

        finished.ShouldBeTrue();

        (await Fixture.CountAsync("SELECT count(*) FROM identity.task_queues")).ShouldBe(
            0,
            "The claim and the terminal delete committed as one, which is what makes a handler's "
            + "own write and its \"this task is done\" the same commit.");
    }

    private static TaskEnqueueRequest Seed(int n) => new(
        Queue,
        string.Create(CultureInfo.InvariantCulture, $"task-{n:000}"),
        Actor: "seed");

    private async Task EnqueueAsync(IReadOnlyCollection<TaskEnqueueRequest> tasks)
    {
        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        (await queue.PushIfNotExistsAsync(tasks, CancellationToken.None)).ShouldBe(tasks.Count);
    }
}
