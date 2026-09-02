using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Iam;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Role bindings of a membership.
/// <para>
/// Both foreign keys are modelled. Everything they reach lives in the iam schema and in this one
/// EF model, so nothing here crosses the boundary to the consumer-facing <c>identity</c> schema -
/// which is the line that deliberately carries no keys. Neither relationship declares a navigation
/// property: the role entity belongs to the IAM catalogue slice, and a navigation here would make
/// this file a second opinion about its shape.
/// </para>
/// </summary>
public sealed class UserTenantRoleConfiguration : IEntityTypeConfiguration<UserTenantRole>
{
    public void Configure(EntityTypeBuilder<UserTenantRole> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("user_tenant_roles", IamSchema.Name);
        builder.HasKey(x => x.Id).HasName("pk_user_tenant_roles");

        // Keyed by member, not by user: the same person holds different roles in different
        // tenants, and a user-keyed binding could not say that.
        builder.HasIndex(x => new { x.MemberId, x.RoleId })
            .IsUnique()
            .HasDatabaseName("uk_user_tenant_roles");

        // The membership side needs no index of its own - the unique index above leads with it.
        builder.HasIndex(x => x.RoleId)
            .HasDatabaseName("idx_user_tenant_roles_role");

        builder.HasOne<TenantMember>()
            .WithMany()
            .HasForeignKey(x => x.MemberId)
            .HasConstraintName("fk_user_tenant_roles_member_id")
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne<Role>()
            .WithMany()
            .HasForeignKey(x => x.RoleId)
            .HasConstraintName("fk_user_tenant_roles_role_id")
            .OnDelete(DeleteBehavior.Cascade);
    }
}
