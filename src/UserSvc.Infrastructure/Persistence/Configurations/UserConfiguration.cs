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

        // HasConstraintName, and it is not cosmetic: without it EF names this key
        // fk_user_identities_users_user_id while db/0001 names it user_identities_user_id_fkey, so
        // a database that had both artefacts applied to it carried the SAME foreign key twice under
        // two names - two constraints to validate on every insert, and a schema diff that could
        // never come out clean.
        builder.HasMany(x => x.Identities)
            .WithOne()
            .HasForeignKey(x => x.UserId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("user_identities_user_id_fkey");
    }
}
