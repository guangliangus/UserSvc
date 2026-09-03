namespace UserSvc.Infrastructure.Persistence.Tasks;

/// <summary>
/// One unit of async work in <c>identity.task_queues</c>: the persistence shape of a queue row.
/// <para>
/// It lives in the infrastructure ring beside <see cref="Outbox.OutboxMessage"/> and for the same
/// reason - a queue row is plumbing, not a domain concept, and nothing in Domain or Application
/// has an opinion about it. What crosses the port boundary is
/// <c>UserSvc.Application.Ports.Platform.QueuedTask</c>; this type never leaves this assembly.
/// </para>
/// <para>
/// <b>It carries no domain events and is never soft-deleted</b>, which is why it needs neither the
/// <c>Entity</c> base class the outbox interceptor drains nor a global query filter. Both absences
/// are deliberate: see <see cref="Repositories.TaskQueueRepository"/> for what that means for the
/// raw SQL the six queue operations are written in.
/// </para>
/// </summary>
public sealed class TaskQueueEntry
{
    public int Id { get; set; }

    /// <summary>The runner pool that owns the row. Exactly one handler is registered per value.</summary>
    public string QueueName { get; set; } = string.Empty;

    /// <summary>
    /// The producer's idempotency key, unique within the queue.
    /// <para>
    /// Opaque text on purpose. It is whatever identifies the unit of work to the capability that
    /// enqueued it, which is what lets every producer push unconditionally and let the unique
    /// index decide.
    /// </para>
    /// </summary>
    public string TaskId { get; set; } = string.Empty;

    /// <summary>Claim order within the queue; higher is claimed first. Never negative
    /// (<c>chk_task_queues_priority</c>).</summary>
    public int Priority { get; set; }

    /// <summary>The handler's input, as a JSON object. Held as raw JSON text and parsed by the
    /// handler, so the driver needs no dynamic-JSON opt-in - the same choice
    /// <c>iam.menus.name</c> made.</summary>
    public string PayloadJson { get; set; } = "{}";

    /// <summary>The earliest time a runner may claim the row. Retry backoff is expressed by
    /// pushing this into the future, which is why the queue needs no separate delay column.</summary>
    public DateTimeOffset DeliverOn { get; set; }

    /// <summary>True while a worker holds the row. The claim index covers the false side of this
    /// column, so a claimed row leaves it for as long as the claim lasts.</summary>
    public bool Popped { get; set; }

    /// <summary>When <see cref="Popped"/> last became true, or null while unclaimed. This is the
    /// age the stale-claim reclaim measures, so null has to mean "not claimed" rather than
    /// "claimed at the epoch".</summary>
    public DateTimeOffset? PoppedAt { get; set; }

    /// <summary>The runner instance holding the claim, so an operator can tie a stuck row back to
    /// a pod. Empty rather than null while unclaimed, following this project's shape for audit
    /// text.</summary>
    public string PoppedBy { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    /// <summary>Who enqueued the row. <b>Not nullable</b> - the Go original had this column as
    /// nullable TEXT, which is against this project's convention for a new table.</summary>
    public string CreatedBy { get; set; } = string.Empty;

    /// <summary>Who last claimed or re-armed the row.</summary>
    public string UpdatedBy { get; set; } = string.Empty;
}
