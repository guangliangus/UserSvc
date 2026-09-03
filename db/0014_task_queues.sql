-- =============================================================================
-- 0014 · identity.task_queues: the database-backed generic async task queue.
--
-- Run by hand (decision 14): DDL first, code second. Idempotent and re-runnable.
-- Depends on nothing but the identity schema; no foreign key, by design (see below).
--
-- WHAT IT IS. One row is one unit of async work: a queue_name naming the runner pool that owns
-- it, a task_id that is the caller's idempotency key, a JSON payload, and the claim bookkeeping
-- (deliver_on, popped, popped_at, popped_by). Workers claim rows with
-- FOR UPDATE SKIP LOCKED, so every pod of this service can poll the same queue_name without two
-- of them ever handling the same row.
--
-- IT IS DORMANT ON PURPOSE, NOT DEAD BY ACCIDENT. The mechanism ships with Tasks:WorkerCount = 0,
-- which is the kill switch and also the shipped default: no runner polls this table until a
-- deployment turns it on (decision 02 - one image, two deployment shapes, a config switch
-- deciding who runs what). The Go service ships the same way. Its only handler there is the FCM
-- topic sync, which belongs to the notification service and is deliberately NOT ported, so this
-- table has no production producer or consumer in user-svc yet. What will use it: any capability
-- that needs at-least-once retried background work owned by this service, enqueued in the same
-- transaction as the row that caused it.
--
-- WHY THE identity SCHEMA. This is cross-cutting plumbing rather than a user- or back-office
-- concept, and the service already made that call once: identity.outbox_messages is equally
-- platform-ish and lives here. The two alternatives lose. A third schema would need its own
-- grants, its own place in the apply order and its own line in every reset/projection list, and
-- buys no isolation - it is the same service, the same connection and the same transaction.
-- The iam schema is a bounded context (back-office authorisation) that no key may cross, and a
-- queue that will carry consumer-plane work has no business there. uam belongs to the Go service
-- and is read-only to us. So: identity, beside the outbox, for the same reason.
--
-- WHY THERE IS NO FOREIGN KEY. task_id is TEXT and deliberately opaque - it is whatever
-- idempotency key the producing capability chooses (an id, a composite, a hash). A key to one
-- table would fix the queue to one producer, which is exactly the coupling a generic queue
-- exists to avoid.
--
-- WHY ROWS ARE PHYSICALLY DELETED, against the project's "avoid physical deletes" convention.
-- That convention is about RECORDS - things somebody will later ask "what happened to this" of.
-- A row here is transient WORK, and it has no history worth keeping: what the task did is
-- recorded by whatever the handler wrote, in that handler's own tables. Three concrete costs of
-- the alternative:
--   1. The (queue_name, task_id) slot has to be freed. A terminal row occupying it would refuse
--      every future re-reconcile of the same subject - the queue would accept each task exactly
--      once for the lifetime of the database.
--   2. A status column would have to enter both the unique index and the claim index, so every
--      Pop would pay to skip a growing tail of finished rows.
--   3. The table would grow without bound in normal operation, with nobody reading the growth.
-- The delete is a repository operation, not DDL: nothing in this script destroys data, so the
-- second application is still a no-op.
--
-- TWO DEFECTS OF THE GO ORIGINAL (docs/db/V19 there) ARE FIXED HERE, NOT COPIED:
--   1. Its index was (queue_name, popped, deliver_on DESC, priority DESC, id) while its Pop
--      orders by priority DESC, deliver_on ASC, id ASC. Both the column order and the direction
--      of deliver_on disagree with the query, so the index cannot serve the sort: the plan had
--      to read every candidate row of the queue and sort it before applying LIMIT. The index
--      below is built for the statement actually issued.
--   2. Its created_by / updated_by were nullable TEXT. Here they are NOT NULL DEFAULT '', which
--      is this project's shape for audit columns on a new table.
-- A THIRD, found while testing this one and fixed in the repository rather than the DDL: Go's
-- stale-claim reclaim re-arms a recovered row with deliver_on = NOW(). A claimed row's deliver_on
-- is already in the past - Pop is the only claimer and it claims only due rows - so the write buys
-- nothing, and because deliver_on is the claim order's second key it sends the recovered row to the
-- BACK of its priority band, behind everything that arrived while it was stuck. Here the reclaim
-- leaves deliver_on alone.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.task_queues
(
    id           SERIAL      NOT NULL,
    queue_name   TEXT        NOT NULL,
    task_id      TEXT        NOT NULL,
    priority     INTEGER     NOT NULL DEFAULT 0,
    payload_json JSONB       NOT NULL DEFAULT '{}'::jsonb,
    deliver_on   TIMESTAMPTZ NOT NULL DEFAULT now(),
    popped       BOOLEAN     NOT NULL DEFAULT false,
    -- Nullable, and one of the few places in this schema where NULL carries information: "this
    -- row is not claimed by anybody". The stale-row reclaim reads it as an age, and an age of
    -- zero or the epoch would both be lies about an unclaimed row.
    popped_at    TIMESTAMPTZ,
    popped_by    TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by   TEXT        NOT NULL DEFAULT '',
    updated_by   TEXT        NOT NULL DEFAULT '',
    CONSTRAINT pk_task_queues PRIMARY KEY (id),
    CONSTRAINT chk_task_queues_priority CHECK (priority >= 0)
);

COMMENT ON TABLE  identity.task_queues IS 'Generic database-backed async task queue, partitioned by queue_name';
COMMENT ON COLUMN identity.task_queues.queue_name IS 'Runner pool this row belongs to; one handler per value';
COMMENT ON COLUMN identity.task_queues.task_id IS 'Producer-chosen idempotency key, unique within the queue';
COMMENT ON COLUMN identity.task_queues.priority IS 'Claim order within the queue; higher is claimed first';
COMMENT ON COLUMN identity.task_queues.payload_json IS 'Handler input as a JSON object';
COMMENT ON COLUMN identity.task_queues.deliver_on IS 'Earliest time a runner may claim the row';
COMMENT ON COLUMN identity.task_queues.popped IS 'True while a worker holds the row';
COMMENT ON COLUMN identity.task_queues.popped_at IS 'When popped last became true; NULL while unclaimed';
COMMENT ON COLUMN identity.task_queues.popped_by IS 'Runner instance that claimed the row';

-- Unconditional enqueue. Every producer pushes with ON CONFLICT (queue_name, task_id) DO NOTHING
-- and lets the first writer win, so no caller has to read-then-insert and no two concurrent
-- callers can create two rows for one unit of work. Freeing this slot is what the terminal delete
-- is for.
CREATE UNIQUE INDEX IF NOT EXISTS uk_task_queues_queue_name_task_id
    ON identity.task_queues (queue_name, task_id);

-- The claim index, built for the statement Pop actually issues:
--     WHERE queue_name = $1 AND popped = false AND deliver_on <= now()
--     ORDER BY priority DESC, deliver_on ASC, id ASC
--     LIMIT $2 FOR UPDATE SKIP LOCKED
-- so the key columns are the equality column first and then the three sort keys in the query's
-- own order AND direction. That is the whole point: an index whose order matches the ORDER BY
-- lets the scan stop after LIMIT rows, while one that does not - the Go original - forces every
-- unclaimed row of the queue through a sort before the LIMIT can apply.
-- deliver_on sits between two sort keys, so it cannot bound the scan, but it is in the index and
-- is therefore checked without touching the heap.
-- Partial on popped = false, matching the predicate verbatim so the planner's proof is trivial:
-- a claimed row leaves the index for as long as it is claimed, which keeps the hot index the size
-- of the backlog rather than the size of the table.
CREATE INDEX IF NOT EXISTS ix_task_queues_ready
    ON identity.task_queues (queue_name, priority DESC, deliver_on, id)
    WHERE popped = false;

-- The stale-claim reclaim, once a minute: popped = true AND popped_at < cutoff. Partial on the
-- other side of the same boolean, so the two indexes partition the table and neither carries rows
-- it can never answer for. Not queue-scoped, because a crashed pod has to be recovered from
-- whatever queue it was serving, and nobody knows which one that was.
CREATE INDEX IF NOT EXISTS ix_task_queues_stale
    ON identity.task_queues (popped_at)
    WHERE popped = true;
