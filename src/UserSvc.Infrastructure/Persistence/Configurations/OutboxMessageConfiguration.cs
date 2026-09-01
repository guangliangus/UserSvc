using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Infrastructure.Persistence.Outbox;

namespace UserSvc.Infrastructure.Persistence.Configurations;

public sealed class OutboxMessageConfiguration : IEntityTypeConfiguration<OutboxMessage>
{
    public void Configure(EntityTypeBuilder<OutboxMessage> builder)
    {
        builder.ToTable("outbox_messages");
        builder.HasKey(x => x.Id);

        builder.HasIndex(x => x.MessageId).IsUnique();

        // The dispatcher's pickup index: it covers undelivered rows only, so a row leaves the
        // index once it has been published.
        builder.HasIndex(x => new { x.OccurredAt, x.Id })
            .HasFilter("dispatched_at IS NULL");
    }
}
