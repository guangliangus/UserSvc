using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps <see cref="Role"/> onto <c>iam.roles</c>.
/// <para>
/// Five check constraints ride on this table, and each encodes a rule the application also states in
/// a readable sentence. The duplication is on purpose: the service refuses first with a message an
/// operator can act on, and the constraint is what makes the rule true of the data regardless of
/// which code path wrote it.
/// </para>
/// </summary>
public sealed class RoleConfiguration : IEntityTypeConfiguration<Role>
{
    /// <summary>The back-office authorisation schema. Separate from <c>identity</c> because
    /// consumer identity and back-office authorisation are different bounded contexts, and no
    /// foreign key crosses between them.</summary>
    private const string IamSchemaName = "iam";

    public void Configure(EntityTypeBuilder<Role> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("roles", IamSchemaName, table =>
        {
            table.HasCheckConstraint(
                "chk_roles_owner_type", "owner_type IN ('SYSTEM','COMPANY','SUPPLIER')");

            table.HasCheckConstraint(
                "chk_roles_category", "category IN ('', 'platform', 'supplier', 'company')");

            // An administrator role is by construction a platform role: its holders inherit the
            // widest delegation ceiling, and a tenant must not be able to mint one.
            table.HasCheckConstraint(
                "chk_roles_admin_system", "NOT is_admin OR owner_type = 'SYSTEM'");

            // Self-loop guard only. Deeper cycles are refused by the service, which walks the
            // ancestor chain - SQL cannot express that here.
            table.HasCheckConstraint(
                "chk_roles_parent_not_self", "parent_role_id IS DISTINCT FROM id");

            // A tenant's own role is pinned to its own dimension; a platform role picks freely,
            // which is how the platform writes a template for suppliers.
            table.HasCheckConstraint(
                "chk_roles_category_owner",
                """
                owner_type = 'SYSTEM'
                OR category = ''
                OR (owner_type = 'COMPANY' AND category = 'company')
                OR (owner_type = 'SUPPLIER' AND category = 'supplier')
                """);
        });

        builder.HasKey(x => x.Id);

        // Reproduced from the live schema; see MenuConfiguration for why the model carries them.
        builder.Property(x => x.Category).HasDefaultValueSql("''::text");
        builder.Property(x => x.OwnerType).HasDefaultValueSql($"'{RoleOwnerTypes.System}'::text");
        // No store default on is_admin, for the reason spelled out in FeedbackTypeConfiguration.
        // The consequence here was milder - the store default agreed with the CLR default, so
        // omitting the column landed on the right value anyway - but it is the same warning on
        // every boot and the same trap underneath: the day someone flips this default to true,
        // "create a non-admin role" starts creating admin roles. EF now always writes the value.
        // db/0005 keeps the column's DEFAULT false.

        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(x => x.UpdatedAt).HasDefaultValueSql("now()");

        // NOTE: the live unique key is an EXPRESSION index -
        //   (owner_type, COALESCE(owner_code, ''), code)
        // which EF cannot model, so it is declared in the DDL script only. It is left out here on
        // purpose rather than replaced by a plain unique index on code: that would be a stricter
        // constraint than the database actually has, and the model would then disagree with the
        // rows. The service refuses a duplicate code globally anyway, which is stricter still and
        // is where the answer the client sees comes from.
        builder.HasIndex(x => x.ParentRoleId).HasDatabaseName("idx_roles_parent");

        builder.HasIndex(x => new { x.OwnerType, x.OwnerCode })
            .HasDatabaseName("idx_roles_owner")
            .HasFilter("owner_type <> 'SYSTEM'");

        builder.HasOne<Role>()
            .WithMany()
            .HasForeignKey(x => x.ParentRoleId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("roles_parent_role_id_fkey");
    }
}
