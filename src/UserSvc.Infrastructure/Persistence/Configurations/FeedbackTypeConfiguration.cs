using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Feedback;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps <see cref="FeedbackType"/> onto <c>identity.feedback_types</c>.
/// <para>
/// The key is the text <c>code</c>, not a surrogate <c>SERIAL</c>. That is the live shape and it is
/// the right one here: the code is the value the client submits and the value
/// <c>feedback.type_code</c> references, so a surrogate key would add a join to every read and
/// change the wire contract to buy nothing.
/// </para>
/// <para>
/// There is no query filter on <c>is_active</c>. Retired categories must stay readable, or a
/// submission filed under one becomes unjoinable the day it is retired; filtering is the
/// repository's job on the one query where it applies.
/// </para>
/// </summary>
public sealed class FeedbackTypeConfiguration : IEntityTypeConfiguration<FeedbackType>
{
    public void Configure(EntityTypeBuilder<FeedbackType> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("feedback_types");
        builder.HasKey(x => x.Code);

        // Never generated: the code is written by whoever seeds or adds the category.
        builder.Property(x => x.Code).ValueGeneratedNever();

        builder.Property(x => x.Labels)
            .HasColumnType("jsonb")
            .HasDefaultValueSql($"'{FeedbackType.EmptyLabelsJson}'::jsonb");

        builder.Property(x => x.IsActive).HasDefaultValueSql("true");
        builder.Property(x => x.SortOrder).HasDefaultValueSql("0");
        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(x => x.UpdatedAt).HasDefaultValueSql("now()");
    }
}
