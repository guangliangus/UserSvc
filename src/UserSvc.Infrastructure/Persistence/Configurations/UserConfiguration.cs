using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Users;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Team DDL conventions: every string is <c>text</c> (length checked in code), timestamps are
/// <c>timestamptz</c>, rows are never deleted physically (a <c>status</c> column plus a global
/// query filter), and concurrency rides on <c>xmin</c>.
/// </summary>
public sealed class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("users");
        builder.HasKey(x => x.Id);

        // Decision 15: optimistic concurrency with no schema change; on conflict SaveChanges
        // throws and the API maps it to 409.
        builder.UseXminConcurrencyToken();

        // Soft delete: every query automatically excludes deleted rows.
        // Note: raw SQL that bypasses EF does not go through this filter and must carry its own
        // status predicate.
        builder.HasQueryFilter(x => x.Status != UserStatuses.Deleted);

        // Domain events are transient and live in memory only; they are never persisted here.
        builder.Ignore(x => x.DomainEvents);

        builder.HasIndex(x => x.BirthDateHash);

        builder.HasMany(x => x.Identities)
            .WithOne()
            .HasForeignKey(x => x.UserId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
