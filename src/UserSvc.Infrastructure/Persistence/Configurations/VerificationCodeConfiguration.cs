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
/// Three indexes serve the statements this table runs. The send path's retirement UPDATE and the
/// ticket consume both ride the (target_hash, purpose, ...) index; the verify candidate SELECT has
/// its own; the conditional UPDATE that follows it goes by primary key. The miss classification
/// queries target_hash + purpose + code_hash with <b>no</b> state filter and so cannot use the
/// partial index the candidate SELECT uses: it falls back to the unfiltered (target_hash,
/// created_at) index and filters the rest in memory. That runs only on a failed verify and reads
/// one target's history - but history accumulates here, since rows are never deleted, so a target
/// sent thousands of codes makes a failed verify measurably slower than a successful one, and the
/// unfiltered index keeps it a bounded index read rather than a growing sequential scan.
/// </para>
/// <para>
/// There is deliberately <b>no</b> (device_id_hash, created_at) index, though the risk-control
/// spec pairs it with the target one. It backed only the device-dimension "count sends from the DB
/// when Redis is down" fallback, and that fallback was never wired - nothing calls
/// <c>CountInWindow</c> - so the index was written on every send and read by nothing. It is dropped
/// in db/0003_verification.sql; this configuration and that script must stay in step (gate 04).
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

        // The unfiltered (target_hash, created_at) index. Its live reader is the miss
        // classification on a failed verify - (target_hash, purpose, code_hash) with no state
        // filter, which the partial indexes above cannot serve - not the never-wired risk-control
        // fallback. The target-dimension fallback COUNT rides it too; the index stands on the
        // verify path alone. See db/0003_verification.sql for the EXPLAIN numbers.
        builder.HasIndex(x => new { x.TargetHash, x.CreatedAt });

        // No (device_id_hash, created_at) index: it backed only the device-dimension fallback COUNT,
        // which no caller reaches, so it was pure write amplification on every send. Dropped in
        // db/0003_verification.sql (DROP INDEX IF EXISTS). Recreate it there and here together, and
        // prove it with EXPLAIN, if the device fallback is ever actually implemented.
    }
}
