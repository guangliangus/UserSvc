using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Verification;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps <see cref="VerificationCode"/> onto <c>identity.verification_codes</c>.
/// <para>
/// <b>No <c>xmin</c> concurrency token here</b>, unlike the other tables. Optimistic concurrency
/// protects a read-modify-write, and this table has none: every state change is a single
/// conditional UPDATE whose WHERE clause carries the precondition, so the database - not a
/// re-read - decides which of two racing verifies wins. Adding a token would turn a race the
/// database already resolves correctly into a 409 the client cannot act on.
/// </para>
/// <para>
/// Four indexes serve seven statements, and one of the seven is only partly covered - worth naming
/// rather than glossing. The send path's retirement UPDATE and the ticket consume both ride the
/// (target_hash, purpose, ...) index; the verify candidate SELECT has its own; the conditional
/// UPDATE that follows it goes by primary key; the two risk-control counts have one each. The
/// exception is the miss classification, which queries target_hash + purpose + code_hash with
/// <b>no</b> state filter and so cannot use the partial index the candidate SELECT uses: it falls
/// back to the unfiltered (target_hash, created_at) index and filters the rest in memory. That is
/// acceptable because it only runs on a failed verify and only ever reads one target's history -
/// but history does accumulate here, since rows are never deleted, so a target that has been sent
/// thousands of codes makes a failed verify measurably slower than a successful one.
/// </para>
/// </summary>
public sealed class VerificationCodeConfiguration : IEntityTypeConfiguration<VerificationCode>
{
    public void Configure(EntityTypeBuilder<VerificationCode> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("verification_codes");
        builder.HasKey(x => x.Id);

        // The verify hot path: newest live row for this target, purpose and code. created_at
        // descends inside the index so the ORDER BY is free rather than a sort of every code ever
        // sent to that address.
        builder.HasIndex(x => new { x.TargetHash, x.Purpose, x.CodeHash, x.CreatedAt })
            .IsDescending(false, false, false, true)
            .HasFilter("consumed_at IS NULL");

        // The consume hot path, and the same index the send path uses to retire the previous live
        // code (it needs only the leading target_hash, purpose columns).
        builder.HasIndex(x => new { x.TargetHash, x.Purpose, x.VerificationTicketHash })
            .HasFilter("consumed_at IS NULL");

        // The two risk-control fallback counts. Unfiltered on purpose: they count history,
        // including the rows the other indexes deliberately exclude.
        builder.HasIndex(x => new { x.TargetHash, x.CreatedAt });
        builder.HasIndex(x => new { x.DeviceIdHash, x.CreatedAt });
    }
}
