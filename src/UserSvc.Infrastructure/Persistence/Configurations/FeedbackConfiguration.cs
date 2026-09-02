using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Feedback;
using UserSvc.Domain.Users;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps <see cref="FeedbackSubmission"/> onto <c>identity.feedback</c>.
/// <para>
/// The table keeps its singular name. <c>feedback</c> is a mass noun whose plural is itself, so
/// <c>feedbacks</c> would be worse English as well as a rename of a table that already exists with
/// rows in it and a foreign key pointing at it.
/// </para>
/// <para>
/// Column defaults, index names and the check constraint are reproduced from the live database.
/// They are not decoration: CI gate 04 diffs the EF-generated script against <c>db/*.sql</c>, so a
/// default present in one and absent from the other is reported as drift on every run.
/// </para>
/// </summary>
public sealed class FeedbackConfiguration : IEntityTypeConfiguration<FeedbackSubmission>
{
    public void Configure(EntityTypeBuilder<FeedbackSubmission> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("feedback", table => table.HasCheckConstraint(
            "chk_feedback_status",
            $"status IN ('{FeedbackStatuses.Pending}','{FeedbackStatuses.Reviewed}','{FeedbackStatuses.Resolved}')"));

        builder.HasKey(x => x.Id);

        // No xmin concurrency token, unlike users and sessions. A submission is inserted once and
        // never updated by this service, so there is no second writer for a token to detect.

        builder.Property(x => x.ImageUrls)
            .HasColumnType("jsonb")
            .HasDefaultValueSql($"'{FeedbackSubmission.EmptyImageUrlsJson}'::jsonb");

        builder.Property(x => x.Status).HasDefaultValueSql($"'{FeedbackStatuses.Pending}'::text");
        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(x => x.UpdatedAt).HasDefaultValueSql("now()");

        builder.HasIndex(x => x.UserId).HasDatabaseName("idx_feedback_user");
        builder.HasIndex(x => x.Status).HasDatabaseName("idx_feedback_status");
        builder.HasIndex(x => x.TypeCode).HasDatabaseName("idx_feedback_type");

        // RESTRICT on both, and neither is ever exercised: user rows are only ever soft-disabled
        // and a category is retired with is_active rather than deleted. The constraints exist so
        // that a hand-written fix-up script cannot orphan a submission.
        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(x => x.UserId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("feedback_user_id_fkey");

        builder.HasOne<FeedbackType>()
            .WithMany()
            .HasForeignKey(x => x.TypeCode)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("feedback_type_code_fkey");
    }
}
