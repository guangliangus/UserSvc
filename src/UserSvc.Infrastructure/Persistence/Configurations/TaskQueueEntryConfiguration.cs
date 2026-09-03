using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Infrastructure.Persistence.Tasks;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps <see cref="TaskQueueEntry"/> onto <c>identity.task_queues</c> (db/0014_task_queues.sql).
/// <para>
/// <b>It is in the consumer schema because that is where this service's cross-cutting plumbing
/// already lives</b> - <c>identity.outbox_messages</c> is equally platform-ish and equally
/// un-user-ish. A third schema for one generic table would need its own grants, its own place in
/// the apply order and its own line in every reset and projection list, and would buy no
/// isolation: same service, same connection, same transaction. The reasoning is written out in
/// full in the script header.
/// </para>
/// <para>
/// <b>No column default is declared here, and that is the safe direction.</b> The DDL puts a
/// default on nine of the thirteen columns; declaring them here as well would make EF omit a
/// column from the INSERT whenever the property holds its CLR default, which is how
/// <c>iam.backend_identities.provider_details</c> silently wrote NULLs (db/README.md). Nothing in
/// this service inserts a queue row through the change tracker anyway - every write is an explicit
/// statement in <see cref="Repositories.TaskQueueRepository"/> that names its columns - so the
/// defaults exist purely for a hand-written INSERT and belong to the database alone.
/// </para>
/// </summary>
public sealed class TaskQueueEntryConfiguration : IEntityTypeConfiguration<TaskQueueEntry>
{
    public void Configure(EntityTypeBuilder<TaskQueueEntry> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("task_queues", table => table.HasCheckConstraint(
            "chk_task_queues_priority", "priority >= 0"));

        builder.HasKey(x => x.Id).HasName("pk_task_queues");

        builder.Property(x => x.PayloadJson).HasColumnType("jsonb");

        // Unconditional enqueue: every producer pushes with ON CONFLICT (queue_name, task_id) DO
        // NOTHING and lets the first writer win, so nobody has to read-then-insert and two
        // concurrent producers cannot create two rows for one unit of work.
        builder.HasIndex(x => new { x.QueueName, x.TaskId })
            .IsUnique()
            .HasDatabaseName("uk_task_queues_queue_name_task_id");

        // The claim index, keyed for the statement Pop actually issues: the equality column first,
        // then the three sort keys in the ORDER BY's own order AND direction, so the scan can stop
        // after LIMIT rows instead of sorting the whole backlog. The Go original's index disagreed
        // with its own query on both counts - see the script header.
        //
        // IsDescending(false, true, false, false) is what puts DESC on priority alone. HasFilter's
        // text is reproduced verbatim from the DDL, both because CI gate 04 compares index
        // definitions as PostgreSQL renders them and because the planner's proof that the query
        // may use a partial index is trivial when the predicate is spelled the same way.
        builder.HasIndex(
                x => new { x.QueueName, x.Priority, x.DeliverOn, x.Id },
                "ix_task_queues_ready")
            .IsDescending(false, true, false, false)
            .HasFilter("popped = false")
            .HasDatabaseName("ix_task_queues_ready");

        // The stale-claim reclaim's index, partial on the other side of the same boolean: the two
        // partition the table, so neither carries rows it can never answer for.
        builder.HasIndex(x => x.PoppedAt, "ix_task_queues_stale")
            .HasFilter("popped = true")
            .HasDatabaseName("ix_task_queues_stale");
    }
}
