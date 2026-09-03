using System.Globalization;
using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Shouldly;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Tasks;
using UserSvc.Infrastructure.Persistence;
using UserSvc.Infrastructure.Tasks;
using UserSvc.IntegrationTests.Infrastructure;

namespace UserSvc.IntegrationTests;

/// <summary>
/// The task queue as a running mechanism: real worker pods, the real
/// <see cref="TaskQueueRunner"/> and <see cref="TaskQueueReclaimer"/>, a real handler and a real
/// PostgreSQL.
/// <para>
/// <b>Why this file exists on top of <see cref="TaskQueueTests"/> and the unit tests.</b> Those
/// prove the six statements are the right statements and that the loop makes the right decisions
/// against a fake clock and a fake queue. Neither can answer the question this queue is built to
/// answer - <i>do N pods polling one table process each row exactly once?</i> - because that
/// question is about two connections racing inside PostgreSQL, and there is only one runner loop
/// per queue in one host. So the tests below start several worker pods against one database and
/// assert on the union of what their handlers actually saw.
/// <para>
/// It is also the file that answers "does shipping this change the running service at all", which
/// is the promise <c>Tasks:WorkerCount = 0</c> makes and the reason this port is safe to merge with
/// no handler in it - see
/// <see cref="WithTheShippedDefaultsAFreshApiHostNeitherPollsNorTouchesTheQueueTable"/>.
/// </para>
/// </para>
/// <para>
/// <b>Every wait here is a poll for a condition, never a sleep for a duration</b>, except the two
/// places where the absence of an event is the assertion - the kill switch and the dormant host -
/// and those two are honest about what they are: a fixed window during which something would have
/// happened if it were going to.
/// </para>
/// </summary>
public sealed class TaskQueueWorkerTests(ServiceFixture fixture) : IntegrationTest(fixture)
{
    /// <summary>The one queue these tests use - the name <see cref="JournalTaskHandler"/> serves.</summary>
    private const string Queue = JournalTaskHandler.Queue;

    /// <summary>
    /// The ceiling on every wait for a runner to do something. Generous on purpose: it is a
    /// failure bound rather than an expected duration - the polls it waits for take tens of
    /// milliseconds - and a bound tight enough to trip on a loaded CI machine turns a real failure
    /// into an unread flake.
    /// </summary>
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How long the two "nothing happened" tests watch for. Twenty-five times the poll interval a
    /// switched-on pod is configured with here, so a pod that was polling at all would have polled
    /// dozens of times inside it.
    /// </summary>
    private static readonly TimeSpan QuietWindow = TimeSpan.FromSeconds(2.5);

    // -------------------------------------------------------------- 1 · exactly once, under load

    /// <summary>
    /// <b>The property this whole mechanism exists for.</b> Four worker pods poll one queue at the
    /// same time, against one database, with 240 rows and six worker slots each - and every row
    /// must reach exactly one handler.
    /// <para>
    /// The assertion is on the union of what the handlers were given, not on the absence of an
    /// exception: a double-claimed row does not throw anywhere. It runs the side effect twice and
    /// the second terminal delete comes back "already gone", which is precisely why
    /// <see cref="ITaskQueue.DeleteAsync"/> returns a bool that this test collects.
    /// </para>
    /// <para>
    /// <b>Mutation-tested, because a concurrency test that has never seen the race is a
    /// decoration.</b> Measured in a scratch copy of the repository, twice each:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Dropping the row lock entirely - no <c>FOR UPDATE</c> in the claim's CTE
    /// - fails this test hard and repeatably: 60 and 66 tasks were handed to a second worker, out
    /// of 240 and 258 deliveries of 240 tasks. The outer <c>UPDATE ... FROM candidate</c> joins on
    /// the id alone, so when a second statement's re-check runs after the first one committed there
    /// is nothing left in it to notice that the row is now claimed - it claims it again and returns
    /// it again.</description></item>
    /// <item><description>Keeping <c>FOR UPDATE</c> but dropping only <c>SKIP LOCKED</c> leaves
    /// this test <b>passing</b>, in the same 0.7 s, and that is worth knowing rather than
    /// glossing: the lock makes the second claimant wait, and PostgreSQL then re-checks
    /// <c>popped = false</c> against the committed version and drops the row, so the result is
    /// still correct - just serialised. What that mutation breaks is
    /// <see cref="TaskQueueTests.ASecondPollerStepsOverRowsAHeldTransactionHasLockedInsteadOfWaitingForThem"/>,
    /// which fails after blocking for its whole ten-second deadline. The two tests are therefore
    /// not duplicates: this one pins correctness, that one pins that pods do not queue behind each
    /// other.</description></item>
    /// </list>
    /// <para>
    /// The handler holds each task for a few milliseconds so the window a broken claim needs is
    /// wide enough for the failure to be reliable rather than lucky. Unmutated, the run is 240
    /// deliveries of 240 tasks with no second attempt, and all four runner ids appear among them -
    /// so the pods really did overlap rather than one of them getting there first.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task FourWorkerPodsSharingOneQueueRunEveryTaskExactlyOnce()
    {
        const int tasks = 240;
        const int pods = 4;

        var alreadyGone = new List<string>();
        var journal = new TaskJournal(async context =>
        {
            // Long enough that a claim from another pod can land in the middle of this one, which
            // is the window a broken claim would show up in. Short enough that 240 of them over 24
            // slots is a second of test time.
            await Task.Delay(Random.Shared.Next(4, 12), context.CancellationToken);

            if (!await context.Queue.DeleteAsync(context.Task.Id, context.CancellationToken))
            {
                lock (alreadyGone)
                {
                    alreadyGone.Add(context.Task.TaskId);
                }
            }
        });

        await EnqueueAsync([.. Enumerable.Range(1, tasks).Select(n => Seed(n))]);

        var settings = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Tasks:WorkerCount"] = "6",
        };

        var farm = new List<TaskWorkerHost>();

        try
        {
            foreach (var _ in Enumerable.Range(1, pods))
            {
                farm.Add(await TaskWorkerHost.StartAsync(Fixture, journal, settings));
            }

            (await journal.WaitForCompletionsAsync(tasks, Timeout)).ShouldBeTrue(
                farm[0].Diagnose(journal));
        }
        finally
        {
            foreach (var pod in farm)
            {
                await pod.DisposeAsync();
            }
        }

        var deliveries = journal.Deliveries;
        var handledTwice = deliveries
            .Where(delivery => delivery.Attempt > 1)
            .Select(delivery => delivery.TaskId)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        // First, because it is the failure this queue exists to prevent and the one a passing
        // count could hide: a task delivered twice ran its side effect twice.
        handledTwice.ShouldBeEmpty(
            string.Create(
                CultureInfo.InvariantCulture,
                $"{handledTwice.Count} task(s) reached a second worker, out of {deliveries.Count} "
                + $"deliveries of {tasks} tasks. Both workers ran the side effect, so the queue "
                + $"guaranteed less than the table it is built on."));

        alreadyGone.ShouldBeEmpty(
            "A terminal delete that found no row is the same failure seen from the other side: the "
            + "first worker had already finished the task this one was handed.");

        deliveries.Select(delivery => delivery.TaskId).Distinct(StringComparer.Ordinal).Count()
            .ShouldBe(tasks, "Every enqueued task has to have been handled - none may be left behind.");

        deliveries.Count.ShouldBe(
            tasks,
            "The two assertions above hold from both ends, so this can only fail if a task id was "
            + "delivered twice without the journal counting the second one - which would mean the "
            + "journal, not the queue, is what is broken.");

        deliveries.Select(delivery => delivery.PoppedBy).Distinct(StringComparer.Ordinal).Count()
            .ShouldBeGreaterThan(
                1,
                "All the work was claimed by one runner id, so the pods never actually overlapped "
                + "and this test proved nothing about concurrency.");

        (await Fixture.CountAsync("SELECT count(*) FROM identity.task_queues")).ShouldBe(
            0, "Every handler deleted its own row, so the queue must be empty.");
    }

    // ------------------------------------------------- 2 and 4 · one row per task, and its reuse

    /// <summary>
    /// The unconditional enqueue and the terminal delete, seen from the runner: a task enqueued
    /// twice is handled once, and once it is finished the same subject can be enqueued again.
    /// <para>
    /// Both halves are one property in practice. A producer reconciling something calls push every
    /// time it changes, so the queue has to collapse the duplicates <b>and</b> then accept the next
    /// one after the work is done - which is why the terminal path is a delete rather than a status
    /// column, and why that is worth asserting through a real handler rather than only through the
    /// port.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task ATaskEnqueuedTwiceIsHandledOnceAndItsSlotIsFreeForTheNextTime()
    {
        var journal = new TaskJournal();

        await using var scope = Fixture.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

        (await queue.PushIfNotExistsAsync(
                [new TaskEnqueueRequest(Queue, "reconcile-7", Actor: "producer-a")],
                CancellationToken.None))
            .ShouldBe(1);

        (await queue.PushIfNotExistsAsync(
                [new TaskEnqueueRequest(Queue, "reconcile-7", Actor: "producer-b")],
                CancellationToken.None))
            .ShouldBe(0, "The second producer's push is a success that inserted nothing.");

        await using var pod = await TaskWorkerHost.StartAsync(Fixture, journal);

        (await journal.WaitForCompletionsAsync(1, Timeout)).ShouldBeTrue(pod.Diagnose(journal));

        // The window in which a second row would have been claimed, had the duplicate created one.
        (await Poll.UntilAsync(() => journal.Deliveries.Count > 1, TimeSpan.FromMilliseconds(500)))
            .ShouldBeFalse("Two deliveries means the duplicate push created a second unit of work.");

        (await Fixture.CountAsync("SELECT count(*) FROM identity.task_queues")).ShouldBe(0);

        // The same subject needs doing again - which is what the delete freed the slot for.
        (await queue.PushIfNotExistsAsync(
                [new TaskEnqueueRequest(Queue, "reconcile-7", Actor: "producer-a")],
                CancellationToken.None))
            .ShouldBe(
                1,
                "A terminal row left behind would refuse every later reconcile of the same "
                + "subject, for the life of the database.");

        (await journal.WaitForCompletionsAsync(2, Timeout)).ShouldBeTrue(pod.Diagnose(journal));

        var deliveries = journal.Deliveries;

        deliveries.Select(delivery => delivery.TaskId).ShouldBe(["reconcile-7", "reconcile-7"]);
        deliveries[0].RowId.ShouldNotBe(
            deliveries[1].RowId,
            "Two separate units of work, not one row delivered twice: the second is a new row that "
            + "reused the freed slot.");

        (await Fixture.CountAsync("SELECT count(*) FROM identity.task_queues")).ShouldBe(0);
    }

    // ------------------------------------------------------------------ 3 · retry with backoff

    /// <summary>
    /// A handler that re-arms its own task gets it back - but not before the backoff it asked for
    /// has passed, and with the claim cleared so whoever takes it next owns it outright.
    /// <para>
    /// The delay comes from the real <see cref="TaskRetryBackoff"/>, so the number is the one a
    /// handler would actually produce, and it is a <b>duration</b> rather than an instant on
    /// purpose: <c>deliver_on</c> is computed as <c>now() + delay</c> by the database that will
    /// later test it, so the window cannot be wrong by this pod's clock skew. The interval between
    /// the two deliveries is measured to confirm the row really was held back rather than merely
    /// re-armed.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task AReArmedTaskComesBackToAHandlerOnlyAfterItsBackoffHasPassed()
    {
        var backoff = TaskRetryBackoff.Delay(1, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2));

        backoff.ShouldBeGreaterThanOrEqualTo(
            TimeSpan.FromSeconds(1), "Attempt one of a one-second base is a one-second delay plus jitter.");

        var journal = new TaskJournal(async context => await (context.Attempt == 1
            ? context.Queue.ReArmAsync(
                context.Task.Id, backoff, "handler-attempt-1", context.CancellationToken)
            : context.Queue.DeleteAsync(context.Task.Id, context.CancellationToken)));

        await EnqueueAsync([Seed(1)]);

        await using var pod = await TaskWorkerHost.StartAsync(Fixture, journal);

        (await journal.WaitForCompletionsAsync(1, Timeout)).ShouldBeTrue(pod.Diagnose(journal));

        // Inside the backoff window: the row is back in the queue, owned by nobody, and not yet due.
        (await Poll.UntilAsync(
                async () => await Fixture.CountAsync(
                    "SELECT count(*) FROM identity.task_queues WHERE popped = false") == 1,
                Timeout))
            .ShouldBeTrue(pod.Diagnose(journal));

        (await Fixture.QueryStringsAsync(
                """
                SELECT popped_by || '|' || coalesce(popped_at::text, 'null') || '|' ||
                       (deliver_on > now())::text || '|' || updated_by
                FROM identity.task_queues
                """))
            .ShouldBe(
                ["|null|true|handler-attempt-1"],
                "The claim is cleared whole - flag, time and owner - and the row is held back until "
                + "its new delivery time. A popped_by left behind would name the runner that gave "
                + "up rather than the one holding the row.");

        (await journal.WaitForCompletionsAsync(2, Timeout)).ShouldBeTrue(pod.Diagnose(journal));

        var deliveries = journal.Deliveries;

        deliveries.Count.ShouldBe(2);
        (deliveries[1].At - deliveries[0].At).ShouldBeGreaterThanOrEqualTo(
            TimeSpan.FromSeconds(1),
            "The second delivery arrived sooner than the backoff, so the delay was not honoured - "
            + "which is how a failing dependency gets hammered by its own retries.");

        deliveries[1].PoppedBy.ShouldBe(
            deliveries[0].PoppedBy,
            "One pod, so the same runner id: the re-armed row was re-claimed through the normal "
            + "claim path rather than handed back inside the handler.");

        (await Fixture.CountAsync("SELECT count(*) FROM identity.task_queues")).ShouldBe(0);
    }

    // ------------------------------------------------------------------------- 6 · claim order

    /// <summary>
    /// Priority beats age, and among equal priorities the task that has been due longest goes
    /// first - all the way through to the handler, with one worker slot so that delivery order is
    /// claim order and nothing else.
    /// </summary>
    [RequiresDockerFact]
    public async Task TasksReachTheHandlerByPriorityAndThenByHowLongTheyHaveBeenDue()
    {
        var journal = new TaskJournal();

        // Enqueued in the opposite order to the one expected, so insertion order cannot be mistaken
        // for claim order. The negative delay is a task that came due half an hour ago.
        await EnqueueAsync(
            [
                new TaskEnqueueRequest(Queue, "low", Priority: 0),
                new TaskEnqueueRequest(Queue, "high-recent", Priority: 9),
                new TaskEnqueueRequest(Queue, "middle", Priority: 5),
                new TaskEnqueueRequest(Queue, "high-overdue", Priority: 9, Delay: TimeSpan.FromMinutes(-30)),
            ]);

        await using var pod = await TaskWorkerHost.StartAsync(Fixture, journal);

        (await journal.WaitForCompletionsAsync(4, Timeout)).ShouldBeTrue(pod.Diagnose(journal));

        journal.TaskIdsInOrder.ShouldBe(
            ["high-overdue", "high-recent", "middle", "low"],
            "One worker slot means the runner claims one row at a time, so this is the claim order "
            + "reaching a handler unchanged.");
    }

    // ------------------------------------------------------------------------ 7 · the kill switch

    /// <summary>
    /// <b>The switch that makes this port safe to merge.</b> With the worker count at zero a pod
    /// claims nothing, ever - and the proof is positive rather than the absence of a log line: the
    /// rows stay unclaimed, the table is not read at all, and then the same rows are processed by a
    /// pod that differs only in that one setting.
    /// <para>
    /// "Not read at all" is measured from PostgreSQL's own table statistics rather than inferred,
    /// because a pod could poll the depth without claiming anything and leave no trace on any row.
    /// The same measurement over the switched-on pod is the calibration: it moves, so a zero above
    /// means nothing happened rather than that the probe cannot see.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task WithTheWorkerCountAtZeroNothingIsClaimedAndTheSameRowsRunOnceItIsRaised()
    {
        var journal = new TaskJournal();

        await EnqueueAsync([Seed(1), Seed(2), Seed(3)]);
        await SettleStatisticsAsync();

        var before = await QueueTableActivityAsync();

        await using (var dormant = await TaskWorkerHost.StartAsync(
            Fixture,
            journal,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Tasks:WorkerCount"] = "0",
            }))
        {
            await Task.Delay(QuietWindow);

            journal.Deliveries.ShouldBeEmpty(
                "A pod with no worker slots handed work to a handler." + dormant.Diagnose(journal));

            dormant.Logs.Contains("Task queue runner is off").ShouldBeTrue(
                "\"Is this pod working the queue\" has no endpoint, so the boot log has to answer "
                + "it. " + dormant.Logs.Dump());

            dormant.Logs.Contains("Task queue reclaim is off with the runner").ShouldBeTrue(
                "The reclaim is worker work too: a pod that claims nothing has no business "
                + "releasing other pods' claims. " + dormant.Logs.Dump());

            await dormant.StopAsync();
        }

        (await QueueTableActivityAsync()).ShouldBe(
            before,
            "A dormant pod read the queue table. WorkerCount = 0 has to mean no poll, no depth "
            + "query and no connection - not \"start and find nothing\".");

        (await Fixture.QueryStringsAsync(
                "SELECT popped::text || '|' || popped_by FROM identity.task_queues ORDER BY task_id"))
            .ShouldBe(
                ["false|", "false|", "false|"],
                "The rows were claimable the whole time and none of them was touched.");

        // The positive control: identical pod, identical rows, one setting different.
        var polling = await QueueTableActivityAsync();

        await using (var working = await TaskWorkerHost.StartAsync(Fixture, journal))
        {
            (await journal.WaitForCompletionsAsync(3, Timeout)).ShouldBeTrue(working.Diagnose(journal));
            await working.StopAsync();
        }

        // Waited for rather than read once: the pod's own statistics are published on PostgreSQL's
        // schedule and not this test's - see SettleStatisticsAsync. Waiting is only correct in this
        // direction, which is why the dormant window above is a fixed one.
        (await Poll.UntilAsync(
                async () => await QueueTableActivityAsync() != polling, TimeSpan.FromSeconds(15)))
            .ShouldBeTrue(
                "The activity probe never moved even for a pod that demonstrably ran three tasks, "
                + "so the equality asserted above would have meant nothing.");

        (await Fixture.CountAsync("SELECT count(*) FROM identity.task_queues")).ShouldBe(0);
    }

    // --------------------------------------------------------------------- 8 · the graceful drain

    /// <summary>
    /// Shutdown stops claiming and then waits: a task already running is allowed to finish, and a
    /// task not yet claimed is left in the queue for the next pod rather than lost or half-done.
    /// <para>
    /// The two assertions that matter are the elapsed stop - a stop that returns instantly while a
    /// handler is still running is a stop that abandoned it - and the handler's own token, which
    /// must <b>not</b> be cancelled: the host's shutdown token is deliberately never linked to it,
    /// so a handler can tell "you took too long" from "we are going down" and does not rush a write
    /// nothing is waiting for.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task AStopWaitsForTheTaskInFlightAndLeavesTheRestOfTheQueueForTheNextPod()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelledDuringDrain = true;

        var journal = new TaskJournal(async context =>
        {
            started.TrySetResult();

            // Waited on the handler's own token, which is what makes the assertion below real: if
            // shutdown cancelled it, this throws and the delete never happens.
            await Task.Delay(TimeSpan.FromSeconds(1), context.CancellationToken);

            cancelledDuringDrain = context.CancellationToken.IsCancellationRequested;

            await context.Queue.DeleteAsync(context.Task.Id, context.CancellationToken);
        });

        await EnqueueAsync([Seed(1), Seed(2), Seed(3)]);

        var pod = await TaskWorkerHost.StartAsync(Fixture, journal);
        TimeSpan stopping;

        try
        {
            (await Task.WhenAny(started.Task, Task.Delay(Timeout))).ShouldBe(
                started.Task, pod.Diagnose(journal));

            stopping = await pod.StopAsync();
        }
        finally
        {
            await pod.DisposeAsync();
        }

        stopping.ShouldBeGreaterThan(
            TimeSpan.FromMilliseconds(500),
            "The stop returned before the task in flight could have finished, so it was abandoned "
            + "rather than drained.");

        cancelledDuringDrain.ShouldBeFalse(
            "The handler's token was cancelled by the shutdown. It must mean one thing only - this "
            + "task overran - or a handler cannot tell a deadline from a deployment.");

        journal.Completed.ShouldBe(1, pod.Diagnose(journal));
        journal.Deliveries.Count.ShouldBe(
            1, "One worker slot, and the stop landed before the second claim." + pod.Diagnose(journal));

        pod.Logs.Contains("is draining").ShouldBeTrue(pod.Logs.Dump());

        (await Fixture.CountAsync(
                "SELECT count(*) FROM identity.task_queues WHERE task_id = @p0",
                journal.Deliveries[0].TaskId))
            .ShouldBe(0, "The task that was in flight finished, which for this handler means its row is gone.");

        (await Fixture.QueryStringsAsync(
                """
                SELECT popped::text || '|' || popped_by FROM identity.task_queues ORDER BY task_id
                """))
            .ShouldBe(
                ["false|", "false|"],
                "The two tasks that were never claimed are still queued and unclaimed - the next "
                + "pod's work, not this one's loss.");
    }

    // ------------------------------------------------ 9 and 5 · a throwing handler, and the reclaim

    /// <summary>
    /// A handler that throws must cost its own task and nothing else: the queue keeps running, the
    /// row stays where an operator can find it - claimed, stamped with the runner that was holding
    /// it - and the reclaim is what eventually gives it back.
    /// <para>
    /// This is the retry path a handler chooses by <b>not</b> catching: slow, bounded by
    /// <c>Tasks:StalePoppedTimeout</c>, and certain. It is turned down to two seconds here so the
    /// whole cycle - throw, claim held, reclaim, redelivery, success - is observable in one test;
    /// in production it is ten minutes, which is the same mechanism at a different number.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task AThrowingHandlerLeavesItsRowForTheReclaimAndTheQueueKeepsRunning()
    {
        var journal = new TaskJournal(context => context.Task.TaskId == "poison" && context.Attempt == 1
            ? throw new InvalidOperationException("the handler could not handle this one")
            : context.Queue.DeleteAsync(context.Task.Id, context.CancellationToken));

        await EnqueueAsync(
            [
                new TaskEnqueueRequest(Queue, "poison", Priority: 9),
                new TaskEnqueueRequest(Queue, "healthy", Priority: 0),
            ]);

        await using var pod = await TaskWorkerHost.StartAsync(
            Fixture,
            journal,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Tasks:StalePoppedTimeout"] = "00:00:02",
                ["Tasks:ReclaimInterval"] = "00:00:00.200",
            });

        // The healthy task is claimed after the poison one threw, which is the isolation assertion:
        // a handler's exception may not end the loop.
        (await journal.WaitForCompletionsAsync(1, Timeout)).ShouldBeTrue(pod.Diagnose(journal));

        journal.TaskIdsInOrder.ShouldBe(
            ["poison", "healthy"],
            "The poison task had the higher priority so it was claimed first, and the loop went on "
            + "to the next one after it threw." + pod.Diagnose(journal));

        pod.Logs.Contains("threw on task poison", LogLevel.Error)
            .ShouldBeTrue(
                "The one record that a task failed is this line, so it has to name the task and "
                + "the handler. " + pod.Logs.Dump());

        (await Fixture.QueryStringsAsync(
                "SELECT task_id || '|' || popped::text || '|' || popped_by FROM identity.task_queues"))
            .Count.ShouldBe(1, "The healthy task deleted its own row; the poison one is still there.");

        var stuck = (await Fixture.QueryStringsAsync(
            "SELECT popped::text || '|' || popped_by FROM identity.task_queues")).Single();

        stuck.StartsWith("true|" + Queue + "-", StringComparison.Ordinal).ShouldBeTrue(
            "A row whose handler threw stays claimed and stamped with the runner that was holding "
            + "it. That stamp is how an operator ties a stuck task back to a pod, and losing it "
            + $"would make the row indistinguishable from one nobody has tried yet. It said: {stuck}");

        // And now the reclaim, which is the retry: the claim is older than the timeout, so it is
        // released, re-claimed and handed to the handler a second time.
        (await journal.WaitForCompletionsAsync(2, Timeout)).ShouldBeTrue(pod.Diagnose(journal));

        journal.Deliveries.Count(delivery => delivery.TaskId == "poison").ShouldBe(
            2, "The reclaim gave the task back exactly once." + pod.Diagnose(journal));

        pod.Logs.Contains("reclaim released 1 claim(s)").ShouldBeTrue(
            "Zero is the healthy value for this counter, so anything above it is a warning saying "
            + "a worker died holding work. " + pod.Logs.Dump());

        (await Fixture.CountAsync("SELECT count(*) FROM identity.task_queues")).ShouldBe(0);

        // The loop is still alive after all of that, which no assertion above quite says.
        await EnqueueAsync([Seed(9)]);

        (await journal.WaitForCompletionsAsync(3, Timeout)).ShouldBeTrue(pod.Diagnose(journal));
    }

    /// <summary>
    /// The other half of the reclaim: it releases the claim a dead pod left behind, and leaves
    /// alone the one a live worker is still honouring.
    /// <para>
    /// Both rows are claimed for the whole of the window the reclaim runs in, and the only
    /// difference between them is the age of the claim - so this is exactly the judgement the
    /// reclaim exists to make. Taking work off a worker that is still doing it would turn every
    /// slow task into a double execution.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task TheReclaimReleasesADeadPodsClaimAndLeavesALiveWorkersAlone()
    {
        var journal = new TaskJournal(async context =>
        {
            // The row a live worker is holding: long enough for several reclaim ticks to pass over
            // it while it is legitimately in flight.
            if (context.Task.TaskId == "held")
            {
                await Task.Delay(TimeSpan.FromSeconds(1.5), context.CancellationToken);
            }

            await context.Queue.DeleteAsync(context.Task.Id, context.CancellationToken);
        });

        await EnqueueAsync([new TaskEnqueueRequest(Queue, "held")]);

        // A pod that died an hour ago holding a task: the row PostgreSQL is left with when a worker
        // is OOM-killed between the claim and the finish. Written straight to the table because
        // nothing in the port can produce it - that is the point of it.
        await Fixture.ExecuteAsync(
            """
            INSERT INTO identity.task_queues
                (queue_name, task_id, priority, payload_json, deliver_on,
                 popped, popped_at, popped_by, created_at, updated_at, created_by, updated_by)
            VALUES (@p0, 'abandoned', 0, '{}'::jsonb, now() - interval '1 hour',
                    true, now() - interval '1 hour', 'crashed-pod-7',
                    now() - interval '1 hour', now() - interval '1 hour', 'seed', 'crashed-pod-7')
            """,
            Queue);

        await using var pod = await TaskWorkerHost.StartAsync(
            Fixture,
            journal,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Tasks:WorkerCount"] = "2",

                // Far longer than the held task takes, so a reclaim of that row could only be a
                // bug; far shorter than the abandoned claim's hour, so that row is due for one.
                ["Tasks:StalePoppedTimeout"] = "00:00:30",
                ["Tasks:ReclaimInterval"] = "00:00:00.200",
            });

        (await journal.WaitForCompletionsAsync(2, Timeout)).ShouldBeTrue(pod.Diagnose(journal));

        var deliveries = journal.Deliveries;

        deliveries.Select(delivery => delivery.TaskId).Order(StringComparer.Ordinal).ShouldBe(
            ["abandoned", "held"]);

        deliveries.ShouldAllBe(
            delivery => delivery.Attempt == 1,
            "The task a live worker was running was handed to a second worker, so the reclaim took "
            + "work off a pod that was still doing it." + pod.Diagnose(journal));

        var recovered = deliveries.Single(delivery => delivery.TaskId == "abandoned").PoppedBy;

        recovered.StartsWith(Queue + "-", StringComparison.Ordinal).ShouldBeTrue(
            "The recovered row was re-claimed by this pod's runner, so the claim really was "
            + "released rather than the row being read while still stamped with the dead pod. It "
            + $"said: {recovered}");

        journal.Deliveries.Count(delivery => delivery.TaskId == "held").ShouldBe(1);

        pod.Logs.Entries.Count(entry => entry.Message.Contains("reclaim released", StringComparison.Ordinal))
            .ShouldBe(
                1,
                "The reclaim ticked roughly eight times during this test and released exactly one "
                + "claim - the abandoned one. " + pod.Logs.Dump());

        (await Fixture.CountAsync("SELECT count(*) FROM identity.task_queues")).ShouldBe(0);
    }

    // ---------------------------------------------------------------- the real host, both answers

    /// <summary>
    /// The whole handler ceremony on the <b>real API host</b>: Program.cs's own
    /// <c>AddTaskQueueWorkers</c>, the real infrastructure DI graph, one
    /// <c>AddTaskHandler&lt;T&gt;()</c> and a positive worker count - and a queued task runs.
    /// <para>
    /// It is the test that keeps the worker hosts in this file honest: everything else here builds
    /// its own container, so without this one a wiring mistake in Program.cs - a hosted service
    /// that never got registered, a scoped handler resolved from the root - would be invisible to
    /// the whole suite.
    /// </para>
    /// <para>
    /// The handler does its work inside <see cref="IUnitOfWork.ExecuteInTransactionAsync"/> rather
    /// than as a bare call, because that is the seam a real handler must use and the one that
    /// breaks: this context is built with <c>EnableRetryOnFailure</c>, so the terminal delete -
    /// which is LINQ - throws inside a transaction the handler opened by hand.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task TheRealApiHostRunsAQueuedTaskThroughTheHandlerCeremony()
    {
        var journal = new TaskJournal(context => context.UnitOfWork.ExecuteInTransactionAsync(
            async token => await context.Queue.DeleteAsync(context.Task.Id, token),
            context.CancellationToken));

        await EnqueueAsync([Seed(1)]);

        await using var host = Fixture.CreateHost(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Tasks:WorkerCount"] = "1",
                ["Tasks:ShortPollInterval"] = "00:00:00.050",
                ["Tasks:LongPollInterval"] = "00:00:00.100",
            },
            configureServices: services =>
            {
                services.AddSingleton(journal);
                services.AddTaskHandler<JournalTaskHandler>();
            });

        // Building the client is what starts the host, and therefore the runner.
        using var client = host.CreateClient();

        (await journal.WaitForCompletionsAsync(1, Timeout)).ShouldBeTrue(journal.Describe());

        var claimedBy = journal.Deliveries[0].PoppedBy;

        claimedBy.StartsWith(Queue + "-", StringComparison.Ordinal).ShouldBeTrue(
            "The runner id names the queue and then the process, which is the shape the Go service "
            + "writes and what an operator greps a stuck row's popped_by for. It said: "
            + claimedBy);

        (await Fixture.CountAsync("SELECT count(*) FROM identity.task_queues")).ShouldBe(
            0, "The handler's terminal delete committed with its own transaction.");

        // The same host is still an API host: the queue is a background tenant, not a takeover.
        using var alive = await client.GetAsync(new Uri("/health/live", UriKind.Relative));
        alive.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    /// <summary>
    /// <b>The question this port has to answer before it can be merged:</b> with the shipped
    /// configuration - which is <c>Tasks:WorkerCount = 0</c> and no handler at all - does having
    /// the task queue in the build change the running service in any observable way?
    /// <para>
    /// Measured rather than assumed, and measured on a host that has rows waiting for it: no row is
    /// claimed, the table is not read once, and the host serves HTTP throughout. The probe's
    /// calibration - that these counters do move when a pod polls - is in
    /// <see cref="WithTheWorkerCountAtZeroNothingIsClaimedAndTheSameRowsRunOnceItIsRaised"/>, where
    /// the same measurement is taken over a pod that demonstrably ran three tasks.
    /// </para>
    /// <para>
    /// <b>Behaviour and not the log, deliberately, and this is the note that saves the next reader
    /// the experiment.</b> The kill switch's log line is asserted on the worker-pod tests but is
    /// unreachable here: <c>Program.cs</c> uses <c>builder.Host.UseSerilog(...)</c>, whose
    /// <c>writeToProviders</c> defaults to false, so Serilog replaces the logger factory and an
    /// <c>ILoggerProvider</c> a test host adds is never called. Passing
    /// <c>writeToProviders: true</c> would make it assertable and was measured before being
    /// rejected: with the Console sink this configuration already has, every line is then written
    /// TWICE to stdout - once by Serilog and once by the framework's own console provider, which
    /// that flag revives (63 lines became 126, in two different formats). That is a cost on every
    /// deployment for one assertion, and the assertions below are the stronger evidence anyway:
    /// no delivery, no row touched, no table activity at all.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task WithTheShippedDefaultsAFreshApiHostNeitherPollsNorTouchesTheQueueTable()
    {
        var journal = new TaskJournal();

        // Three tasks due now: a pod that polls at all would claim them on its first poll.
        await EnqueueAsync([Seed(1), Seed(2), Seed(3)]);
        await SettleStatisticsAsync();

        var before = await QueueTableActivityAsync();

        // No Tasks:* override of any kind, so the worker count is appsettings.json's shipped 0.
        // A handler IS registered, and that is what sharpens the test: the service as it ships has
        // no handler either, so a host without one proves only that two independent things were
        // both missing. With one registered, the kill switch is the single reason nothing happens.
        await using var host = Fixture.CreateHost(
            new Dictionary<string, string>(StringComparer.Ordinal),
            configureServices: services =>
            {
                services.AddSingleton(journal);
                services.AddTaskHandler<JournalTaskHandler>();
            });

        using var client = host.CreateClient();

        using (var alive = await client.GetAsync(new Uri("/health/live", UriKind.Relative)))
        {
            alive.StatusCode.ShouldBe(
                HttpStatusCode.OK, "The host has to be up for the rest of this to mean anything.");
        }

        await Task.Delay(QuietWindow);

        (await QueueTableActivityAsync()).ShouldBe(
            before,
            "A default host read identity.task_queues. The promise of WorkerCount = 0 is that "
            + "merging this port costs a deployment nothing at all - not one statement.");

        journal.Deliveries.ShouldBeEmpty(
            "A registered handler was still handed work on a host that never asked for a worker.");

        (await Fixture.QueryStringsAsync(
                "SELECT popped::text || '|' || popped_by FROM identity.task_queues ORDER BY task_id"))
            .ShouldBe(["false|", "false|", "false|"], "Nothing claimed anything.");
    }

    /// <summary>
    /// A <c>Tasks:*</c> value that cannot be bound costs the queue and nothing else: the host
    /// boots, serves, and the queue stays off.
    /// <para>
    /// This is the rule docs/architecture.md records having been broken ten times, and the two ways
    /// to break it here would both have been natural: <c>ValidateOnStart</c> on an optional section,
    /// or an <c>IOptions.Value</c> read in a hosted service's constructor. Either one turns a typo
    /// in a config map into a service that will not start.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task AnUnbindableTasksSettingCostsTheQueueAndNotTheHost()
    {
        var journal = new TaskJournal();

        await EnqueueAsync([Seed(1)]);

        await using var host = Fixture.CreateHost(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                // Out of the option's [Range(0, 1024)], so ValidateDataAnnotations refuses the
                // whole section on the first read - which is inside the two hosted services.
                ["Tasks:WorkerCount"] = "4096",
                ["Tasks:ShortPollInterval"] = "00:00:00.050",
            },
            configureServices: services =>
            {
                services.AddSingleton(journal);
                services.AddTaskHandler<JournalTaskHandler>();
            });

        using var client = host.CreateClient();

        var userId = await Fixture.SeedUserAsync();
        var signIn = await TokenEndpoint.SignInDeviceAsync(client, userId, "a-phone");

        signIn.Status.ShouldBe(
            HttpStatusCode.OK,
            "A broken task-queue setting stopped a request that has nothing to do with the task "
            + $"queue: {signIn.Error} {signIn.ErrorDescription}");

        await Task.Delay(QuietWindow);

        journal.Deliveries.ShouldBeEmpty(
            "The section is invalid, so the runner must refuse to start rather than run on "
            + "defaults nobody configured.");

        (await Fixture.CountAsync(
                "SELECT count(*) FROM identity.task_queues WHERE popped = false"))
            .ShouldBe(1, "The task is still queued, waiting for a pod whose configuration parses.");
    }

    // --------------------------------------------------------------------------------- helpers

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

    /// <summary>
    /// Every scan, insert, update and delete PostgreSQL has counted against
    /// <c>identity.task_queues</c>. The number itself means nothing; the difference across a window
    /// is "did anybody touch this table".
    /// </summary>
    private async Task<string> QueueTableActivityAsync() => (await Fixture.QueryStringsAsync(
        """
        SELECT 'seq_scan=' || coalesce(seq_scan, 0) || ' idx_scan=' || coalesce(idx_scan, 0)
             || ' inserted=' || coalesce(n_tup_ins, 0) || ' updated=' || coalesce(n_tup_upd, 0)
             || ' deleted=' || coalesce(n_tup_del, 0)
        FROM pg_stat_user_tables
        WHERE relid = 'identity.task_queues'::regclass
        """)).Single();

    /// <summary>
    /// Makes PostgreSQL publish the statistics for what the test itself just did, before opening a
    /// window in which nothing is supposed to happen.
    /// <para>
    /// <b>This is not a paranoid delay, it is the correction of a measurement that was wrong the
    /// first time it was run.</b> A backend accumulates its table counters privately and publishes
    /// them when a transaction ends, but at most once a second - and an idle backend that missed
    /// that window publishes seconds later still. Measured here: a pod that demonstrably claimed
    /// and deleted three rows moved these counters not at all by the time it had stopped, and this
    /// test's own enqueue turned up inside a later test's observation window as ten units of
    /// activity nobody had caused.
    /// </para>
    /// <para>
    /// So: wait past the one-second throttle and give every pool this suite drives a statement to
    /// run, because a pooled backend publishes what it is holding at its next command boundary -
    /// neither statement below touches the queue table, so the settle cannot add to what it is
    /// draining. Then <b>wait for the counters to stop moving</b>, which is the part that actually
    /// makes this reliable: an earlier test's worker pod leaves idle connections in a pool nothing
    /// will use again, and nothing this test can run will make those publish - they do it on
    /// PostgreSQL's own idle timer, seconds later. Two seconds of stillness is the signal that
    /// everything owed has landed. Measured: without this the pending counters of the test that ran
    /// before turned up mid-window as five units of activity, and the assertion below failed for a
    /// reason that had nothing to do with the host it was watching.
    /// </para>
    /// </summary>
    private async Task SettleStatisticsAsync()
    {
        await Task.Delay(TimeSpan.FromSeconds(1.2));

        for (var attempt = 0; attempt < 4; attempt++)
        {
            await Fixture.CountAsync("SELECT 1");

            await using var scope = Fixture.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<UserSvcDbContext>();

            await db.Users.CountAsync();
        }

        var stillness = TimeSpan.FromSeconds(2);
        var cap = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(20);
        var last = await QueueTableActivityAsync();
        var unchangedSince = DateTimeOffset.UtcNow;

        while (DateTimeOffset.UtcNow - unchangedSince < stillness && DateTimeOffset.UtcNow < cap)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(200));

            var current = await QueueTableActivityAsync();

            if (!string.Equals(current, last, StringComparison.Ordinal))
            {
                last = current;
                unchangedSince = DateTimeOffset.UtcNow;
            }
        }
    }
}
