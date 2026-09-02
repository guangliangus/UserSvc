using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>Maps <see cref="RolePermission"/> onto <c>iam.role_permissions</c>.</summary>
public sealed class RolePermissionConfiguration : IEntityTypeConfiguration<RolePermission>
{
    /// <summary>The back-office authorisation schema. Separate from <c>identity</c> because
    /// consumer identity and back-office authorisation are different bounded contexts, and no
    /// foreign key crosses between them.</summary>
    private const string IamSchemaName = "iam";

    public void Configure(EntityTypeBuilder<RolePermission> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("role_permissions", IamSchemaName);
        builder.HasKey(x => x.Id);

        // Reproduced from the live schema; see MenuConfiguration for why the model carries it.
        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");

        builder.HasIndex(x => new { x.RoleId, x.PermissionId })
            .IsUnique()
            .HasDatabaseName("role_permissions_role_id_permission_id_key");

        builder.HasIndex(x => x.RoleId).HasDatabaseName("idx_role_permissions_role_id");
        builder.HasIndex(x => x.PermissionId).HasDatabaseName("idx_role_permissions_permission_id");

        // Cascade both ways: a grant row is meaningless without the role or the point it joins.
        builder.HasOne<Role>()
            .WithMany()
            .HasForeignKey(x => x.RoleId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("role_permissions_role_id_fkey");

        builder.HasOne<Permission>()
            .WithMany()
            .HasForeignKey(x => x.PermissionId)
            .OnDelete(DeleteBehavior.Cascade)
            .HasConstraintName("role_permissions_permission_id_fkey");
    }
}
