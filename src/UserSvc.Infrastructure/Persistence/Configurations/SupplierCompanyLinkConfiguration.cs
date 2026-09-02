using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Suppliers;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps <see cref="SupplierCompanyLink"/> onto <c>iam.supplier_company_links</c>.
/// <para>
/// <b>No foreign keys, and that is the shape of the thing rather than an omission.</b>
/// <c>supplier_code</c> and <c>company_code</c> are logical references into the product master
/// data, which is another service's database; the write path validates them over the master-data
/// port instead. A key here would be unenforceable in the only place a key is worth having.
/// </para>
/// <para>
/// The index names are pinned by hand to the ones the Go table already carries
/// (<c>uk_supplier_links_active</c>, <c>idx_supplier_links_company</c>) rather than to EF's
/// defaults, so the two schemas stay recognisably the same table and CI gate 04 diffs clean against
/// the hand-written DDL.
/// </para>
/// </summary>
public sealed class SupplierCompanyLinkConfiguration : IEntityTypeConfiguration<SupplierCompanyLink>
{
    public void Configure(EntityTypeBuilder<SupplierCompanyLink> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("supplier_company_links", UserSvcDbContext.BackOfficeSchema, table =>
            table.HasCheckConstraint(
                "chk_supplier_links_status",
                $"status IN ('{SupplierCompanyLinkStatuses.Active}', '{SupplierCompanyLinkStatuses.Unlinked}')"));

        builder.HasKey(x => x.Id).HasName("pk_supplier_company_links");

        builder.Property(x => x.Status)
            .HasDefaultValueSql($"'{SupplierCompanyLinkStatuses.Active}'::text");

        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(x => x.UpdatedAt).HasDefaultValueSql("now()");
        builder.Property(x => x.CreatedBy).HasDefaultValue(string.Empty);
        builder.Property(x => x.UpdatedBy).HasDefaultValue(string.Empty);

        // THE invariant of this table: at most one ACTIVE mounting per supplier. It is a partial
        // unique index rather than an application check because it is the only form of the rule
        // that holds against two concurrent mounts - which is also why the mount path takes no
        // lock and lets a lost race surface as a unique violation.
        builder.HasIndex(x => x.SupplierCode)
            .IsUnique()
            .HasFilter($"status = '{SupplierCompanyLinkStatuses.Active}'")
            .HasDatabaseName("uk_supplier_links_active");

        // The reverse read: which suppliers hang off this company. Every tenant-context resolution
        // for a company crosses it, so it is not optional.
        builder.HasIndex(x => x.CompanyCode)
            .HasDatabaseName("idx_supplier_links_company");
    }
}
