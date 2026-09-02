using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>Maps <see cref="RoleMenu"/> onto <c>iam.role_menus</c>.</summary>
public sealed class RoleMenuConfiguration : IEntityTypeConfiguration<RoleMenu>
{
    /// <summary>The back-office authorisation schema. Separate from <c>identity</c> because
    /// consumer identity and back-office authorisation are different bounded contexts, and no
    /// foreign key crosses between them.</summary>
    private const string IamSchemaName = "iam";

    public void Configure(EntityTypeBuilder<RoleMenu> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("role_menus", IamSchemaName);
        builder.HasKey(x => x.Id);

        // Reproduced from the live schema; see MenuConfiguration for why the model carries it.
        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");

        builder.HasIndex(x => new { x.RoleId, x.MenuId }).IsUnique().HasDatabaseName("uk_role_menus");
        builder.HasIndex(x => x.MenuId).HasDatabaseName("idx_role_menus_menu");

        builder.HasOne<Role>()
            .WithMany()
            .HasForeignKey(x => x.RoleId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("role_menus_role_id_fkey");

        builder.HasOne<Menu>()
            .WithMany()
            .HasForeignKey(x => x.MenuId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("role_menus_menu_id_fkey");
    }
}
