using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.TestWhitelist;
using UserSvc.Domain.Users;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps <see cref="TestWhitelistEntry"/> onto <c>identity.test_whitelist_users</c>.
/// <para>
/// <b>It is in the consumer schema, not the back-office one</b>, even though only a platform
/// administrator ever writes it. Every row is about a consumer account, the hot read is a consumer
/// authentication path, and the foreign key that keeps a back-office id out of the table is only
/// expressible inside one schema - no key crosses between <c>identity</c> and <c>iam</c>, by
/// design.
/// </para>
/// </summary>
public sealed class TestWhitelistEntryConfiguration : IEntityTypeConfiguration<TestWhitelistEntry>
{
    public void Configure(EntityTypeBuilder<TestWhitelistEntry> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("test_whitelist_users", table => table.HasCheckConstraint(
            "chk_test_whitelist_users_status",
            $"status IN ('{TestWhitelistStatuses.Active}', '{TestWhitelistStatuses.Removed}')"));

        builder.HasKey(x => x.Id).HasName("pk_test_whitelist_users");

        builder.Property(x => x.Status).HasDefaultValueSql($"'{TestWhitelistStatuses.Active}'::text");
        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(x => x.UpdatedAt).HasDefaultValueSql("now()");
        builder.Property(x => x.CreatedBy).HasDefaultValue(string.Empty);
        builder.Property(x => x.UpdatedBy).HasDefaultValue(string.Empty);

        // One ACTIVE entry per account. It is what makes re-adding somebody revive their old row
        // rather than insert a second one, and it is where the "no duplicates" rule can actually be
        // held against two administrators clicking at once.
        // Both indexes are declared with an explicit MODEL name, which is the only way to have two
        // of them over the same column: the unnamed overload keys the index by its property set, so
        // a second HasIndex(x => x.UserId) silently reconfigures the first one instead of adding
        // another - measured against the generated script, which came back with one index carrying
        // the plain name and the unique filter.
        builder.HasIndex(x => x.UserId, "uk_test_whitelist_users_active")
            .IsUnique()
            .HasFilter($"status = '{TestWhitelistStatuses.Active}'")
            .HasDatabaseName("uk_test_whitelist_users_active");

        // The foreign key column, indexed for the history read (every entry this account ever had,
        // whatever its status) that the partial index above cannot serve, and for the referential
        // check behind the key itself.
        builder.HasIndex(x => x.UserId, "ix_test_whitelist_users_user_id")
            .HasDatabaseName("ix_test_whitelist_users_user_id");

        // RESTRICT, and never exercised: consumer accounts are soft-deleted, never removed. The
        // constraint is here so a hand-written fix-up script cannot whitelist an id that is not a
        // consumer - which is the one way a back-office id could otherwise reach this table and
        // inherit a consumer's membership. No navigation property: the consumer entity belongs to
        // another slice and this configuration must not become a second opinion about its shape.
        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(x => x.UserId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_test_whitelist_users_user_id");
    }
}
