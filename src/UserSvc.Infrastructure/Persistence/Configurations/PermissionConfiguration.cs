using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>Maps <see cref="Permission"/> onto <c>iam.permissions</c>.</summary>
public sealed class PermissionConfiguration : IEntityTypeConfiguration<Permission>
{
    /// <summary>The back-office authorisation schema. Separate from <c>identity</c> because
    /// consumer identity and back-office authorisation are different bounded contexts, and no
    /// foreign key crosses between them.</summary>
    private const string IamSchemaName = "iam";

    public void Configure(EntityTypeBuilder<Permission> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("permissions", IamSchemaName, table =>
            table.HasCheckConstraint("permissions_status_check", "status IN ('ACTIVE','INACTIVE')"));

        builder.HasKey(x => x.Id);

        // Reproduced from the live schema; see MenuConfiguration for why the model carries them.
        builder.Property(x => x.Status).HasDefaultValueSql($"'{PermissionStatuses.Active}'::text");
        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(x => x.UpdatedAt).HasDefaultValueSql("now()");

        builder.HasIndex(x => x.Code).IsUnique().HasDatabaseName("permissions_code_key");
        builder.HasIndex(x => x.MenuId).HasDatabaseName("idx_permissions_menu");

        // RESTRICT is what forces a menu delete to remove its permission points first, in the same
        // transaction - the order is not interchangeable.
        builder.HasOne<Menu>()
            .WithMany()
            .HasForeignKey(x => x.MenuId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("permissions_menu_id_fkey");
    }
}
