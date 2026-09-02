using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// The IAM schema. A bounded context of its own, separate from <c>identity</c>: back-office
/// accounts and consumer accounts are different populations with different lifecycles, and the
/// blueprint asks for that split to be visible in the database rather than only in the code.
/// <para>
/// There are deliberately <b>no foreign keys across the two schemas</b>. A key would make the
/// split cosmetic and would bind the two contexts' deployment and archival to each other.
/// </para>
/// </summary>
internal static class IamSchema
{
    public const string Name = "iam";
}

/// <summary>
/// Membership of a tenant.
/// <para>
/// Note what is <b>not</b> here: an <c>xmin</c> concurrency token. Every write to this table runs
/// under the tenant's advisory lock, so two writers cannot interleave in the first place, and an
/// optimistic token would only add a second, rarer failure mode - plus it would have to be listed
/// explicitly in the one place this table is read with <c>FOR UPDATE</c>, since a system column
/// does not come back from <c>SELECT *</c>.
/// </para>
/// <para>
/// The index names are pinned by hand to the ones the live database already carries. They are not
/// EF's defaults, and letting EF rename them would make CI gate 04 report drift on every run for
/// indexes that are in fact identical.
/// </para>
/// </summary>
public sealed class TenantMemberConfiguration : IEntityTypeConfiguration<TenantMember>
{
    public void Configure(EntityTypeBuilder<TenantMember> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("tenant_members", IamSchema.Name, table =>
        {
            table.HasCheckConstraint(
                "chk_tenant_members_type", "tenant_type IN ('company', 'supplier')");
            table.HasCheckConstraint(
                "chk_tenant_members_status", "status IN ('ACTIVE', 'DISABLED', 'REMOVED')");
        });

        builder.HasKey(x => x.Id).HasName("pk_tenant_members");

        // One row per person per tenant. It is what makes re-adding somebody revive their old row
        // rather than insert a second one - the removal path is a status change, not a delete.
        builder.HasIndex(x => new { x.UserId, x.TenantType, x.TenantCode })
            .IsUnique()
            .HasDatabaseName("uk_tenant_members");

        // At most one whole-dimension row per person per dimension. Two would mean two different
        // role sets both claiming to govern "every company".
        builder.HasIndex(x => new { x.UserId, x.TenantType })
            .IsUnique()
            .HasFilter("scope_all")
            .HasDatabaseName("uk_tenant_members_scope_all");

        // The last-administrator check runs on every membership write, so it gets its own partial
        // index rather than filtering the tenant index at query time.
        builder.HasIndex(x => new { x.TenantType, x.TenantCode })
            .HasFilter("is_admin = true AND status = 'ACTIVE'")
            .HasDatabaseName("idx_tenant_members_admin");

        builder.HasIndex(x => new { x.TenantType, x.TenantCode, x.Status })
            .HasDatabaseName("idx_tenant_members_tenant");

        builder.HasIndex(x => new { x.UserId, x.Status })
            .HasDatabaseName("idx_tenant_members_user");

        // Modelled, not merely declared in the DDL. Both tables live in the iam schema and in one
        // EF model, so leaving this relationship out made the generated model script omit the
        // constraint the DDL declares - which is exactly the difference CI gate 04 reports, and it
        // would have reported it on every run forever. No navigation property is added: the
        // back-office account entity belongs to another slice and this configuration must not
        // become a second opinion about its shape.
        builder.HasOne<BackendUser>()
            .WithMany()
            .HasForeignKey(x => x.UserId)
            .HasConstraintName("fk_tenant_members_user_id")
            .OnDelete(DeleteBehavior.Cascade);
    }
}
