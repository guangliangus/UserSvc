using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Shouldly;
using UserSvc.Infrastructure.Persistence;
using UserSvc.Infrastructure.Persistence.Repositories;
using UserSvc.Infrastructure.Persistence.Tasks;
using Xunit;

namespace UserSvc.UnitTests.Tasks;

/// <summary>
/// The task queue's statements, asserted as text and against the EF model, with no database.
/// <para>
/// Two properties of <c>Pop</c> are invisible at every other level and both are silent when
/// broken. It has to reach PostgreSQL as <b>one top-level statement</b>, because a data-modifying
/// <c>WITH</c> is illegal inside a subquery and EF wraps a <c>FromSql</c> in one the moment
/// anything is composed onto it - so the symptom of composing an <c>OrderBy</c> onto it is a
/// runtime error in a background worker, not a compile error. And its <c>ORDER BY</c> and its
/// <c>popped = false</c> have to agree with <c>ix_task_queues_ready</c>'s key order, direction and
/// filter, because when they drift the query still returns exactly the right rows - it just sorts
/// the whole backlog to do it, which is the defect the Go original shipped with and which no
/// behavioural test can see.
/// </para>
/// <para>
/// The expectations are read out of the EF model rather than written down twice, so changing the
/// index without changing the statement fails here, and so does the reverse.
/// </para>
/// </summary>
public sealed class TaskQueueSqlTests
{
    /// <summary>The claim index, by the name both the model and db/0014_task_queues.sql give it.</summary>
    private const string ClaimIndexName = "ix_task_queues_ready";

    /// <summary>
    /// A context over a connection string nothing is listening on. Every assertion here is about
    /// generated SQL or about model metadata, neither of which opens a connection - so if one of
    /// these tests ever starts talking to a database, it fails instead of passing slowly against
    /// whatever happens to be running on the developer's machine.
    /// </summary>
    private static UserSvcDbContext Context() =>
        new(new DbContextOptionsBuilder<UserSvcDbContext>()
            .UseNpgsql("Host=127.0.0.1;Port=1;Database=none;Username=none;Password=none")
            .UseSnakeCaseNamingConvention()
            .Options);

    [Fact]
    public void PopReachesPostgresAsOneTopLevelStatementRatherThanWrappedInASubquery()
    {
        using var db = Context();

        // The repository's own query, not a copy of it: asserting a rebuilt one would pass while
        // PopAsync composed whatever it liked.
        var generated = Statement(
            TaskQueueRepository.ClaimQuery(db, "fcm_topic_sync", 5, "runner-1").ToQueryString());

        generated.ShouldStartWith(
            "WITH candidate AS (",
            customMessage: "PostgreSQL allows a data-modifying statement inside WITH only at the top level of a "
            + "statement. If EF has wrapped this in SELECT ... FROM (...), every Pop fails at "
            + "runtime with \"WITH clause containing a data-modifying statement must be at the top "
            + "level\" - and nothing but a real database says so.");

        generated.ShouldEndWith(
            "RETURNING q.*",
            customMessage: "The claim and the read are one round trip. A RETURNING that has been projected away "
            + "means EF composed onto the statement, which is the same subquery wrap by another "
            + "route.");

        generated.ShouldNotContain(
            "FROM (",
            customMessage: "Any subquery here is the wrap this test exists to catch.");
    }

    /// <summary>
    /// The predicate has to be the index's filter character for character. A partial index is only
    /// usable when the planner can prove the query's predicate implies it, and "spelled the same
    /// way" is the one form of that proof which needs no cleverness from the planner and no luck
    /// from us.
    /// </summary>
    [Fact]
    public void PopFiltersOnExactlyTheTextTheClaimIndexIsPartialOn()
    {
        using var db = Context();

        var filter = ClaimIndex(db).GetFilter();

        filter.ShouldBe(
            "popped = false",
            "Changing the index filter's spelling without changing the statement's is how a "
            + "partial index quietly stops being usable.");

        var sql = TaskQueueSql.Pop("q", 1, "r").Format;

        sql.ShouldContain(
            filter!,
            customMessage: "Pop must ask for exactly what ix_task_queues_ready covers.");
        TaskQueueSql.CountPending("q").Format.ShouldContain(
            filter!,
            customMessage: "The queue-depth metric reads the same rows Pop claims, so it must be able to use the "
            + "same index.");
    }

    /// <summary>
    /// The ORDER BY has to be the claim index's key columns after the leading equality column, in
    /// the index's own order AND direction. That is what lets the scan stop after LIMIT rows
    /// instead of sorting every claimable row of the queue - measured at 29 buffers against 3,696
    /// for the Go original's index shape, on the same 200,000 rows.
    /// </summary>
    [Fact]
    public void PopOrdersByExactlyTheClaimIndexsKeyOrderAndDirection()
    {
        using var db = Context();

        var index = ClaimIndex(db);
        var columns = index.Properties.Select(property => property.GetColumnName()).ToArray();
        var descending = index.IsDescending;

        columns[0].ShouldBe(
            "queue_name",
            "The index's leading column has to be the one the query has an equality predicate on, "
            + "or the sort columns behind it are unreachable.");

        // Rendered from the index's own metadata: the key columns behind the equality column, each
        // carrying DESC exactly where the index does.
        var expected = string.Join(
            ", ",
            columns.Skip(1).Select((column, offset) =>
                descending?[offset + 1] == true ? $"{column} DESC" : column));

        expected.ShouldBe(
            "priority DESC, deliver_on, id",
            "If this changed, the index changed - check that the change was intended before "
            + "updating the statement to match it.");

        TaskQueueSql.Pop("q", 1, "r").Format.ShouldContain(
            $"ORDER BY {expected}",
            customMessage: "The statement's sort and the index's key order are one decision written in two "
            + "places; when they disagree the query is correct and slow, which no other test sees.");
    }

    /// <summary>
    /// The claim is taken inside the same statement that takes the lock. Split into a select and a
    /// separate update, this passes every single-threaded behavioural test and hands one row to two
    /// workers the first time two pods poll at once.
    /// </summary>
    [Fact]
    public void PopTakesItsLockAndItsClaimInTheSameStatement()
    {
        var sql = TaskQueueSql.Pop("q", 1, "r").Format;

        sql.ShouldContain("FOR UPDATE SKIP LOCKED");
        sql.ShouldContain("UPDATE identity.task_queues q");
        sql.ShouldContain("SET    popped = true");
        sql.ShouldContain("popped_at = now()");
        sql.ShouldContain("WHERE  q.id = candidate.id");
    }

    /// <summary>
    /// Every producer enqueues unconditionally and the first writer wins. Without DO NOTHING the
    /// loser of that race gets SQLSTATE 23505, which aborts its whole transaction - so a second
    /// producer would lose the business write it was enqueueing alongside.
    /// </summary>
    [Fact]
    public void PushIgnoresDuplicatesOnTheQueueAndTaskSlotRatherThanFailing()
    {
        var sql = TaskQueueSql.Push([], [], [], [], [], []).Format;

        sql.ShouldContain(
            "ON CONFLICT (queue_name, task_id) DO NOTHING",
            customMessage: "Naming the columns rather than the constraint is required: "
            + "uk_task_queues_queue_name_task_id is a unique INDEX, and ON CONFLICT ON CONSTRAINT "
            + "does not resolve one.");
    }

    /// <summary>
    /// One clock, and it is PostgreSQL's. Pop tests <c>deliver_on &lt;= now()</c> on the server, so
    /// a backoff or a stale cutoff computed in the pod would be wrong by whatever the two clocks
    /// disagree about - and the symptom is a retry that fires early or late, which looks like a
    /// tuning problem rather than a bug.
    /// </summary>
    [Fact]
    public void EveryTimeTheQueueWritesOrComparesIsTheDatabasesOwnNow()
    {
        TaskQueueSql.Push([], [], [], [], [], []).Format
            .ShouldContain("now() + coalesce(candidate.delay, interval '0')");

        // Asserted without the placeholder index: which number the delay gets depends on the
        // order the arguments appear in, which is not the point being made here.
        TaskQueueSql.ReArm(1, TimeSpan.FromMinutes(1), "actor").Format
            .ShouldContain("deliver_on = now() + {");

        TaskQueueSql.RecoverStale(TimeSpan.FromMinutes(10), "fixer").Format
            .ShouldContain("popped_at < now() - {");

        TaskQueueSql.CountPending("q").Format
            .ShouldContain("deliver_on <= now()");
    }

    /// <summary>
    /// A re-armed row must be claimable cleanly by whoever picks it up next, which means the claim
    /// is released and not merely the delivery time moved. Leaving <c>popped_by</c> behind would
    /// make it a record of who gave up rather than of who holds the row - exactly the field an
    /// operator reads off a stuck row to find the pod.
    /// </summary>
    [Fact]
    public void ReArmAndTheStaleReclaimBothReleaseTheWholeClaimRatherThanJustTheFlag()
    {
        foreach (var sql in new[]
                 {
                     TaskQueueSql.ReArm(1, TimeSpan.Zero, "actor").Format,
                     TaskQueueSql.RecoverStale(TimeSpan.FromMinutes(10), "fixer").Format,
                 })
        {
            sql.ShouldContain("popped = false");
            sql.ShouldContain("popped_at = NULL");
            sql.ShouldContain("popped_by = ''");
        }
    }

    /// <summary>
    /// The reclaim releases the claim and moves nothing else. Stamping <c>deliver_on</c> with the
    /// current time - which the Go original does - sends the recovered row to the back of its
    /// priority band, because <c>deliver_on</c> is the claim order's second key. The row was
    /// already due before it was claimed, so there is nothing to bring forward and everything to
    /// lose by pushing it back.
    /// </summary>
    [Fact]
    public void TheStaleReclaimLeavesTheDeliveryTimeWhereItWasSoRecoveredWorkKeepsItsPlace()
    {
        var sql = TaskQueueSql.RecoverStale(TimeSpan.FromMinutes(10), "fixer").Format;

        sql.ShouldNotContain(
            "deliver_on",
            customMessage: "A claimed row's deliver_on is already in the past - Pop claims only due "
            + "rows - so writing it can only move the row later in the queue.");

        TaskQueueSql.ReArm(1, TimeSpan.FromMinutes(1), "actor").Format.ShouldContain(
            "deliver_on = now() + {",
            customMessage: "A handler's own re-arm is the opposite case: the backoff IS a new "
            + "delivery time, chosen deliberately.");
    }

    /// <summary>
    /// The reclaim must not move any attempt counter. A worker that had already made its side
    /// effect before dying would otherwise lose retry budget for having died, and one that had not
    /// made it has not spent any - so the counter belongs to the handler's own tables, which are
    /// the only ones that know which of those happened.
    /// </summary>
    [Fact]
    public void TheStaleReclaimTouchesNoAttemptCounter()
    {
        var sql = TaskQueueSql.RecoverStale(TimeSpan.FromMinutes(10), "fixer").Format;

        sql.ShouldNotContain("attempt", Case.Insensitive);
        sql.ShouldContain("popped = true", customMessage:
            "It reclaims claimed rows only. Without that predicate it would re-arm the entire "
            + "table, including rows nobody has touched.");
    }

    /// <summary>
    /// The gate-04 trap, held at the model. A default the model declares and db/*.sql does not have
    /// makes EF omit the column from the INSERT expecting the database to fill it in, so the row
    /// lands on NULL - which is what happened to <c>iam.backend_identities.provider_details</c>.
    /// This table's defaults live in the DDL alone; nothing here may declare one.
    /// </summary>
    [Fact]
    public void TheModelDeclaresNoColumnDefaultForTheQueueTable()
    {
        using var db = Context();

        // TryGetDefaultValue, not GetDefaultValue: the latter answers with the CLR default of a
        // value-type property when nothing is configured, so it reports a default on every int,
        // bool and DateTimeOffset column whether one was declared or not. Measured - it flagged
        // six columns on a model that declares none.
        var declared = DesignTimeEntity(db)
            .GetProperties()
            .Where(property =>
                property.TryGetDefaultValue(out _) || property.GetDefaultValueSql() is not null)
            .Select(property => property.GetColumnName())
            .ToArray();

        declared.ShouldBeEmpty(
            "db/0014_task_queues.sql carries the defaults and the model must not: EF omits a "
            + "column from the INSERT when the property holds its CLR default and the model claims "
            + "the database will supply one. Every write to this table names its columns "
            + "explicitly, so the model has nothing to gain by knowing.");
    }

    /// <summary>
    /// The claim index as the <b>design-time</b> model holds it. The runtime model is
    /// read-optimised and throws on <c>IsDescending</c> - "The requested configuration is not
    /// stored in the read-optimized model" - and it is exactly the sort direction this test is
    /// about, so the design-time model is the only one that can answer.
    /// </summary>
    private static IIndex ClaimIndex(UserSvcDbContext db) =>
        DesignTimeEntity(db)
            .GetIndexes()
            .Single(index => index.GetDatabaseName() == ClaimIndexName);

    private static IEntityType DesignTimeEntity(UserSvcDbContext db) =>
        db.GetService<IDesignTimeModel>().Model.FindEntityType(typeof(TaskQueueEntry))!;

    /// <summary>
    /// <c>ToQueryString</c> prefixes the statement with one <c>-- pN='...'</c> line per parameter.
    /// Those are a debugging aid, not part of what PostgreSQL is asked to run, so they are stripped
    /// before any assertion about the statement's shape.
    /// </summary>
    private static string Statement(string queryString) =>
        string.Join(
                Environment.NewLine,
                queryString
                    .Split(Environment.NewLine)
                    .SkipWhile(line => line.StartsWith("-- ", StringComparison.Ordinal)))
            .Trim();
}
