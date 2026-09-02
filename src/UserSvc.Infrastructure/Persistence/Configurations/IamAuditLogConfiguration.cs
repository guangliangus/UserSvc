using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps <see cref="IamAuditLog"/> onto <c>iam.iam_audit_logs</c>.
/// <para>
/// <c>actor_user_id</c> carries <b>no foreign key</b>, and that is not an omission. The actor lives
/// in the back-office account context, and an audit row has to survive the account it names: a
/// cascade would erase the trail of exactly the operator whose actions are most worth keeping.
/// </para>
/// <para>
/// Both timestamped indexes descend, because every query against this table reads the newest entries
/// for one actor or one tenant - a descending index makes that ordering free instead of a sort over
/// the whole history.
/// </para>
/// </summary>
public sealed class IamAuditLogConfiguration : IEntityTypeConfiguration<IamAuditLog>
{
    /// <summary>The back-office authorisation schema. Separate from <c>identity</c> because
    /// consumer identity and back-office authorisation are different bounded contexts, and no
    /// foreign key crosses between them.</summary>
    private const string IamSchemaName = "iam";

    public void Configure(EntityTypeBuilder<IamAuditLog> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("iam_audit_logs", IamSchemaName);
        builder.HasKey(x => x.Id);

        builder.Property(x => x.BeforeData).HasColumnType("jsonb");
        builder.Property(x => x.AfterData).HasColumnType("jsonb");

        // Reproduced from the live schema; see MenuConfiguration for why the model carries it.
        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");

        builder.HasIndex(x => new { x.ActorUserId, x.CreatedAt })
            .IsDescending(false, true)
            .HasDatabaseName("idx_iam_audit_actor");

        builder.HasIndex(x => new { x.TenantType, x.TenantCode, x.CreatedAt })
            .IsDescending(false, false, true)
            .HasDatabaseName("idx_iam_audit_tenant");
    }
}
