namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// The five statements the task queue cannot express through the change tracker, kept here so they
/// can be read - and asserted - without going through a database, following the precedent
/// <see cref="BackendUserSql"/> set.
/// <para>
/// Each one is here for a different reason, and none of them is a preference:
/// </para>
/// <list type="number">
/// <item><description><see cref="Push"/> needs <c>ON CONFLICT DO NOTHING</c>. Through SaveChanges
/// a duplicate is SQLSTATE 23505, which aborts the producer's whole transaction - so the
/// "everybody enqueues unconditionally, first writer wins" contract would become "the second
/// writer loses its business write too".</description></item>
/// <item><description><see cref="Pop"/> needs <c>FOR UPDATE SKIP LOCKED</c> and the claim in ONE
/// statement. EF has no row-lock hint and no way to say "update what this locking select
/// returned".</description></item>
/// <item><description><see cref="ReArm"/>, <see cref="RecoverStale"/> and
/// <see cref="CountPending"/> need <c>now()</c> to be evaluated by PostgreSQL. Pop tests
/// <c>deliver_on &lt;= now()</c> on the server, so a backoff or a cutoff computed in the pod would
/// be wrong by whatever the two clocks disagree about.</description></item>
/// </list>
/// <para>
/// They are <c>FormattableString</c>s so every value travels as a parameter. Nothing here
/// concatenates a caller's text into SQL, and nothing here may start to: the arguments include a
/// queue name and a runner id that come from configuration, and an actor that can come from a
/// request.
/// </para>
/// </summary>
public static class TaskQueueSql
{
    /// <summary>
    /// Claims up to <paramref name="limit"/> due rows of one queue and returns them, atomically.
    /// <para>
    /// <b>The CTE takes the locks; the outer UPDATE takes the claim.</b> <c>FOR UPDATE SKIP
    /// LOCKED</c> is what lets every pod poll the same queue at full speed: a poller steps over
    /// rows another poller already holds instead of queueing behind them. <c>RETURNING</c> makes
    /// the claim and the read one round trip, so there is no window in which a row is chosen but
    /// not yet claimed - and therefore no window in which a crash loses it or a second poller
    /// takes it.
    /// </para>
    /// <para>
    /// <b>It must reach PostgreSQL as one top-level statement.</b> A data-modifying statement is
    /// allowed inside <c>WITH</c> only at the top level, and EF wraps a <c>FromSql</c> in
    /// <c>SELECT ... FROM (...)</c> as soon as anything is composed onto it. So the caller composes
    /// nothing that translates - measured: <c>AsNoTracking</c> does not, an <c>OrderBy</c> does -
    /// and <c>TaskQueueSqlTests</c> asserts the emitted statement is still the bare one. Get this
    /// wrong and the failure is a runtime "WITH clause containing a data-modifying statement must
    /// be at the top level", visible nowhere else.
    /// </para>
    /// <para>
    /// <b>The predicate is spelled <c>popped = false</c> character for character as
    /// <c>ix_task_queues_ready</c>'s own filter</b>, so the planner's proof that it may use that
    /// partial index is trivial rather than clever; and the <c>ORDER BY</c> is that index's key
    /// order AND direction, so the scan stops after <c>LIMIT</c> rows. Measured on 200,000 rows
    /// (153,000 of them claimable): index scan, no sort, 29 buffers, 0.65 ms. With the Go
    /// original's index shape instead - <c>(queue_name, popped, deliver_on DESC, priority DESC,
    /// id)</c>, which disagrees with its own query on both column order and direction - the same
    /// query plans a quicksort over 32,000 rows: 3,696 buffers, 13.9 ms, for ten rows.
    /// </para>
    /// </summary>
    /// <param name="queueName">The queue to claim from.</param>
    /// <param name="limit">The most rows to claim.</param>
    /// <param name="poppedBy">The claiming runner's identifier.</param>
    /// <returns>The statement, with every value parameterised.</returns>
    public static FormattableString Pop(string queueName, int limit, string poppedBy) =>
        $"""
         WITH candidate AS (
             SELECT id
             FROM identity.task_queues
             WHERE queue_name = {queueName}
               AND popped = false
               AND deliver_on <= now()
             ORDER BY priority DESC, deliver_on, id
             LIMIT {limit}
             FOR UPDATE SKIP LOCKED
         )
         UPDATE identity.task_queues q
         SET    popped = true,
                popped_at = now(),
                popped_by = {poppedBy},
                updated_at = now(),
                updated_by = {poppedBy}
         FROM   candidate
         WHERE  q.id = candidate.id
         RETURNING q.*
         """;

    /// <summary>
    /// Inserts a whole batch of tasks, ignoring any whose (queue, task id) slot is taken.
    /// <para>
    /// One statement for the batch, zipped out of six parallel arrays by <c>unnest</c>. A statement
    /// per item would be N round trips inside the producer's transaction, and would make a partial
    /// failure mean "some of them enqueued".
    /// </para>
    /// <para>
    /// <c>ON CONFLICT</c> names the two columns rather than the constraint, because
    /// <c>uk_task_queues_queue_name_task_id</c> is a unique INDEX and not a table constraint -
    /// <c>ON CONFLICT ON CONSTRAINT</c> would not resolve it, which is the same trap db/0013
    /// records for <c>uk_menus_code</c>.
    /// </para>
    /// <para>
    /// <c>deliver_on</c> is <c>now() + delay</c>, so a task held back "for five minutes" is due
    /// five minutes after the database says it was enqueued.
    /// </para>
    /// </summary>
    /// <param name="queueNames">Queue name per row.</param>
    /// <param name="taskIds">Idempotency key per row.</param>
    /// <param name="priorities">Priority per row.</param>
    /// <param name="payloads">JSON payload per row, already normalised.</param>
    /// <param name="delays">Delay per row, or null for "immediately".</param>
    /// <param name="actors">Audit actor per row.</param>
    /// <returns>The statement, with every value parameterised.</returns>
    public static FormattableString Push(
        string[] queueNames,
        string[] taskIds,
        int[] priorities,
        string[] payloads,
        TimeSpan?[] delays,
        string[] actors) =>
        $"""
         INSERT INTO identity.task_queues
             (queue_name, task_id, priority, payload_json, deliver_on,
              created_at, updated_at, created_by, updated_by)
         SELECT candidate.queue_name,
                candidate.task_id,
                candidate.priority,
                candidate.payload_json::jsonb,
                now() + coalesce(candidate.delay, interval '0'),
                now(),
                now(),
                candidate.actor,
                candidate.actor
         FROM unnest({queueNames}, {taskIds}, {priorities}, {payloads}, {delays}, {actors})
              AS candidate(queue_name, task_id, priority, payload_json, delay, actor)
         ON CONFLICT (queue_name, task_id) DO NOTHING
         """;

    /// <summary>
    /// Releases one claimed row back to the queue, due <paramref name="delay"/> from the database's
    /// own now: retry with backoff.
    /// <para>
    /// <c>popped_at</c> and <c>popped_by</c> are cleared as well as <c>popped</c>. The next runner
    /// to claim the row owns it outright rather than inheriting the identity of whoever gave up on
    /// it, which is what makes <c>popped_by</c> worth reading off a stuck row.
    /// </para>
    /// <para>
    /// No attempt counter is touched here. The retry budget belongs to whatever the handler is
    /// reconciling, because only the handler knows whether an attempt achieved anything.
    /// </para>
    /// </summary>
    /// <param name="id">The row to release.</param>
    /// <param name="delay">How long before it may be claimed again.</param>
    /// <param name="actor">Audit actor.</param>
    /// <returns>The statement, with every value parameterised.</returns>
    public static FormattableString ReArm(int id, TimeSpan delay, string actor) =>
        $"""
         UPDATE identity.task_queues
         SET    deliver_on = now() + {delay},
                popped = false,
                popped_at = NULL,
                popped_by = '',
                updated_at = now(),
                updated_by = {actor}
         WHERE  id = {id}
         """;

    /// <summary>
    /// Reclaims every row that has been claimed longer than <paramref name="timeout"/>, so a
    /// crashed or OOM-killed pod cannot pin work forever.
    /// <para>
    /// It releases the claim and changes nothing else - in particular no attempt counter moves. A
    /// worker that had already made its side effect before dying must not lose retry budget for
    /// having died, and one that had not made it has not spent any.
    /// </para>
    /// <para>
    /// <b><c>deliver_on</c> is deliberately left where it was, which is where this diverges from
    /// the Go original.</b> Go re-arms a reclaimed row with <c>deliver_on = NOW()</c>. That is
    /// unnecessary - a claimed row's <c>deliver_on</c> is already in the past, because
    /// <see cref="Pop"/> is the only thing that claims rows and it only claims due ones - and it is
    /// actively harmful: the claim order's second key is <c>deliver_on</c>, so stamping it with
    /// <c>now()</c> sends the reclaimed row to the BACK of its priority band, behind everything
    /// that arrived while it was stuck. The work that has been waiting longest is exactly the work
    /// that just came back, and moving it last is the opposite of what the sort is for. Measured:
    /// a reclaimed row and a never-claimed sibling enqueued in the same statement come back in id
    /// order, rather than the reclaimed one going second.
    /// </para>
    /// <para>
    /// Not scoped to a queue, because a crashed pod has to be recovered from whatever queue it was
    /// serving and nothing it left behind says which one that was. <c>popped_at IS NOT NULL</c> is
    /// deliberately absent: the comparison already excludes NULL, and no path through
    /// <see cref="TaskQueueRepository"/> can produce a claimed row without a claim time, because
    /// <see cref="Pop"/> writes both in one statement.
    /// </para>
    /// <para>
    /// Measured on 200,000 rows with 30,000 claimed: bitmap index scan on
    /// <c>ix_task_queues_stale</c>, 33 buffers and 0.7 ms to find the 24,961 stale ones. That index
    /// is partial on the other side of the same boolean as the claim index, so the two partition
    /// the table - it was 320 kB against the claim index's 12 MB on that data.
    /// </para>
    /// </summary>
    /// <param name="timeout">How long a claim may stand before it is presumed abandoned.</param>
    /// <param name="actor">Audit actor, so a reclaim is distinguishable from a handler's own
    /// re-arm when somebody reads the table.</param>
    /// <returns>The statement, with every value parameterised.</returns>
    public static FormattableString RecoverStale(TimeSpan timeout, string actor) =>
        $"""
         UPDATE identity.task_queues
         SET    popped = false,
                popped_at = NULL,
                popped_by = '',
                updated_at = now(),
                updated_by = {actor}
         WHERE  popped = true
           AND  popped_at < now() - {timeout}
         """;

    /// <summary>
    /// Counts the rows of one queue that are claimable right now - unclaimed and due.
    /// <para>
    /// The predicate is character for character the one <see cref="Pop"/> issues, which is the
    /// whole reason this is not written in LINQ: "not popped" comes out of LINQ as
    /// <c>NOT (popped)</c>, which is equivalent but no longer the clause
    /// <c>ix_task_queues_ready</c> carries, so whether the metric can use the index would depend on
    /// how hard the planner tries to prove it. Measured on 200,000 rows: index-only scan, zero heap
    /// fetches, 2.4 ms for a queue with 32,000 claimable rows.
    /// </para>
    /// <para>
    /// <c>count(*)</c> is cast to <c>int</c> because <c>count()</c> is <c>bigint</c> in PostgreSQL
    /// while this measures a backlog, not a population. <c>AS "Value"</c> is the column name EF's
    /// scalar query API expects.
    /// </para>
    /// </summary>
    /// <param name="queueName">The queue to measure.</param>
    /// <returns>The statement, with every value parameterised.</returns>
    public static FormattableString CountPending(string queueName) =>
        $"""
         SELECT count(*)::int AS "Value"
         FROM identity.task_queues
         WHERE queue_name = {queueName}
           AND popped = false
           AND deliver_on <= now()
         """;
}
