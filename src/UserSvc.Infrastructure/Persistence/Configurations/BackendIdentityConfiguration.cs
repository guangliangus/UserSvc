using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.BackOffice;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Back-office login identities.
/// <para>
/// <b>Six partial unique indexes, in two families, and both families are needed.</b> The first
/// says an address belongs to at most one back-office account; the second says an account has at
/// most one identity of each kind. Neither implies the other: without the first, two accounts could
/// claim one mailbox and sign-in would pick whichever row the planner returned; without the second,
/// one account could accumulate three mailboxes, and "the account's email address" would stop being
/// a well-defined thing for password reset to send a code to.
/// </para>
/// <para>
/// All six are filtered on ACTIVE, which is what makes an identity revocable: a revoked row keeps
/// its history, stops matching, and frees the address for someone else.
/// </para>
/// </summary>
public sealed class BackendIdentityConfiguration : IEntityTypeConfiguration<BackendIdentity>
{
    /// <summary>
    /// The filters are written out per type rather than generated, and the SQL text has to match
    /// the migration script byte for byte - PostgreSQL compares partial-index predicates as text,
    /// so a difference in spacing produces a second index rather than a match.
    /// </summary>
    private const string ActiveEmail = $"status = '{BackendIdentityStatuses.Active}' AND identity_type = '{BackendIdentityTypes.Email}'";

    private const string ActivePhone = $"status = '{BackendIdentityStatuses.Active}' AND identity_type = '{BackendIdentityTypes.Phone}'";

    private const string ActiveOtp = $"status = '{BackendIdentityStatuses.Active}' AND identity_type = '{BackendIdentityTypes.Otp}'";

    public void Configure(EntityTypeBuilder<BackendIdentity> builder)
    {
        builder.ToTable(
            "backend_identities",
            UserSvcDbContext.BackOfficeSchema,
            table => table.HasCheckConstraint(
                "chk_backend_identity_type", "identity_type IN ('email', 'phone', 'OTP')"));

        builder.HasKey(x => x.Id);
        builder.UseXminConcurrencyToken();

        builder.Property(x => x.UserId).HasColumnName("user_id");
        builder.Property(x => x.IdentityType).HasColumnType("character varying(20)");
        builder.Property(x => x.Provider).HasColumnType("character varying(50)").HasDefaultValue(string.Empty);
        builder.Property(x => x.IdentifierHash).HasColumnType("character varying(64)");
        builder.Property(x => x.KeyVersion).HasColumnType("character varying(20)");

        // Kept as jsonb rather than flattened into text columns: what an upstream sends about a
        // subject differs per upstream and changes without asking us, and a column per attribute
        // would make every one of those changes a migration.
        // jsonb, with the live column's own default. An INSERT that omits it lands on '{}'
        // rather than NULL, so every reader sees an object; the column stays nullable because the
        // live rows do.
        builder.Property(x => x.ProviderDetails)
            .HasColumnType("jsonb")
            .HasDefaultValueSql("'{}'::jsonb");

        builder.Property(x => x.Status).HasDefaultValue(BackendIdentityStatuses.Active);
        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(x => x.UpdatedAt).HasDefaultValueSql("now()");

        builder.HasIndex(x => x.UserId).HasDatabaseName("idx_backend_identity_user");

        // One account per address, per kind of address.
        //
        // NAMED overload, and that is not cosmetic. HasIndex(x => new { ... }) identifies an index
        // BY ITS PROPERTY LIST: calling it three times over the same two properties configures one
        // index three times, and the last call silently wins. That is exactly what happened here -
        // the model carried only the OTP index out of each family of three, so a database created
        // from this model would let two accounts claim the same mailbox. The string argument makes
        // each one a distinct index in the MODEL; HasDatabaseName is still needed on top of it,
        // because the model name is not the database name and the naming convention rewrites it.
        builder.HasIndex(
                x => new { x.IdentityType, x.IdentifierHash },
                "idx_backend_identity_unique_email_active")
            .IsUnique()
            .HasFilter(ActiveEmail)
            .HasDatabaseName("idx_backend_identity_unique_email_active");

        builder.HasIndex(
                x => new { x.IdentityType, x.IdentifierHash },
                "idx_backend_identity_unique_phone_active")
            .IsUnique()
            .HasFilter(ActivePhone)
            .HasDatabaseName("idx_backend_identity_unique_phone_active");

        builder.HasIndex(
                x => new { x.IdentityType, x.IdentifierHash },
                "idx_backend_identity_unique_otp_active")
            .IsUnique()
            .HasFilter(ActiveOtp)
            .HasDatabaseName("idx_backend_identity_unique_otp_active");

        // One address per account, per kind of address. Same named overload, same reason.
        builder.HasIndex(
                x => new { x.UserId, x.IdentityType },
                "idx_backend_identity_user_email_active")
            .IsUnique()
            .HasFilter(ActiveEmail)
            .HasDatabaseName("idx_backend_identity_user_email_active");

        builder.HasIndex(
                x => new { x.UserId, x.IdentityType },
                "idx_backend_identity_user_phone_active")
            .IsUnique()
            .HasFilter(ActivePhone)
            .HasDatabaseName("idx_backend_identity_user_phone_active");

        builder.HasIndex(
                x => new { x.UserId, x.IdentityType },
                "idx_backend_identity_user_otp_active")
            .IsUnique()
            .HasFilter(ActiveOtp)
            .HasDatabaseName("idx_backend_identity_user_otp_active");

    }
}
