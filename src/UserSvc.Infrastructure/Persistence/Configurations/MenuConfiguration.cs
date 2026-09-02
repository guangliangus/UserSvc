using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps <see cref="Menu"/> onto <c>iam.menus</c>.
/// <para>
/// The IAM tables live in their own schema, not in <c>identity</c>: back-office authorisation is a
/// different bounded context from consumer identity, and there are deliberately <b>no foreign keys
/// between the two</b>. A join across that line would make the separation cosmetic.
/// </para>
/// <para>
/// Two columns are <c>jsonb</c> and stay that way. <c>name</c> carries seven locales, so flattening
/// it to one string would discard six of them; <c>audience</c> is a JSON string array rather than
/// <c>text[]</c>, which keeps both sides free of array-type mapping. Both are held as raw JSON text
/// and parsed by the domain, which needs no dynamic-JSON opt-in from the driver.
/// </para>
/// </summary>
public sealed class MenuConfiguration : IEntityTypeConfiguration<Menu>
{
    /// <summary>The back-office authorisation schema. Separate from <c>identity</c> because
    /// consumer identity and back-office authorisation are different bounded contexts, and no
    /// foreign key crosses between them.</summary>
    private const string IamSchemaName = "iam";

    public void Configure(EntityTypeBuilder<Menu> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("menus", IamSchemaName, table =>
        {
            // Reproduced from the live database: closed value sets the back office relies on.
            table.HasCheckConstraint("chk_menus_audience", "jsonb_typeof(audience) = 'array'");
            table.HasCheckConstraint("chk_menus_status", "status IN ('ACTIVE','INACTIVE')");
        });

        builder.HasKey(x => x.Id);

        // Column defaults are reproduced from the live schema. They are not decoration: CI gate 04
        // diffs the EF-generated script against db/*.sql, so a default that exists in the database
        // and not in the model is drift the gate reports on every run. They also make a row inserted
        // by anything other than this service - a seed, a fix-up script - land in the same shape.
        builder.Property(x => x.Name).HasColumnType("jsonb").HasDefaultValueSql("'{}'::jsonb");
        builder.Property(x => x.Audience).HasColumnType("jsonb")
            .HasDefaultValueSql($"'{Menu.DefaultAudienceJson}'::jsonb");
        builder.Property(x => x.SortOrder).HasDefaultValueSql("0");
        builder.Property(x => x.Status).HasDefaultValueSql($"'{MenuStatuses.Active}'::text");
        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(x => x.UpdatedAt).HasDefaultValueSql("now()");

        // Index names are the live ones. They are not referenced by any statement, but keeping them
        // means a dump of this database and a dump of the source database differ in nothing.
        builder.HasIndex(x => x.Code).IsUnique().HasDatabaseName("uk_menus_code");
        builder.HasIndex(x => x.ParentId).HasDatabaseName("idx_menus_parent");

        // RESTRICT, not cascade: deleting a group must not silently take its whole branch with it.
        builder.HasOne<Menu>()
            .WithMany()
            .HasForeignKey(x => x.ParentId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("menus_parent_id_fkey");
    }
}
