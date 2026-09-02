using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.BackOffice;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// The back-office account table, in its own <c>iam</c> schema.
/// <para>
/// <b>A different schema, and no foreign key across the boundary.</b> Back-office accounts are a
/// different bounded context from consumer identities: separate lifecycles, separate id spaces,
/// separate audiences. The schema split is what keeps that separation enforceable rather than
/// merely intended - nothing can join the two planes back together by accident, and permissions can
/// be granted per schema.
/// </para>
/// <para>
/// Two shapes here follow the live database rather than the team's own DDL preferences, because
/// existing rows are the constraint: <c>status</c> is <c>varchar(20)</c> rather than <c>text</c>,
/// and most string columns are nullable rather than NOT NULL DEFAULT ''. Both are recorded as
/// known divergences; neither is worth a data migration on its own.
/// </para>
/// </summary>
public sealed class BackendUserConfiguration : IEntityTypeConfiguration<BackendUser>
{
    public void Configure(EntityTypeBuilder<BackendUser> builder)
    {
        builder.ToTable(
            "backend_users",
            UserSvcDbContext.BackOfficeSchema,
            table =>
            {
                // Reproduced from the live schema. They are closed value sets the back office
                // relies on: a status the console cannot render is worse than a rejected write.
                table.HasCheckConstraint(
                    "chk_backend_users_status", "status IN ('PENDING', 'ACTIVE', 'DISABLED')");
                table.HasCheckConstraint(
                    "chk_backend_users_origin", "origin IN ('INTERNAL', 'EXTERNAL')");
            });

        builder.HasKey(x => x.Id);

        // Optimistic concurrency with no schema change, as on the consumer tables. It does not
        // protect the super-administrator flag - that guard lives inside a SQL predicate, because
        // xmin can only detect a conflict between two writers, not a rule about the whole table.
        builder.UseXminConcurrencyToken();

        builder.Property(x => x.Status)
            .HasColumnType("character varying(20)")
            .HasDefaultValue(BackendUserStatuses.Pending);

        builder.Property(x => x.Origin).HasDefaultValue(BackendUserOrigins.Internal);

        // Declared as store defaults so that an INSERT which does not mention them - which is what
        // EF emits while they hold their CLR defaults - still lands on false and zero. That is the
        // mechanical form of "no creation path can mint a super administrator": the column is not
        // in the statement at all.
        builder.Property(x => x.IsSuperAdmin).HasDefaultValue(false);
        builder.Property(x => x.TokenVersion).HasDefaultValue(0);

        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(x => x.UpdatedAt).HasDefaultValueSql("now()");

        // The directory filters on status on every page load. Named as the live database names it,
        // so a schema diff against the source system stays quiet.
        builder.HasIndex(x => x.Status).HasDatabaseName("idx_backend_users_status");

        builder.HasMany(x => x.Identities)
            .WithOne()
            .HasForeignKey(x => x.UserId)
            // Cascade, unlike the consumer plane's restrict. An identity is meaningless without the
            // account it names, and the live schema already cascades - restricting here would make
            // EF emit a foreign key that contradicts the one the database has.
            .OnDelete(DeleteBehavior.Cascade);
    }
}
