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

        // NO store default on is_active, and that is a correctness fix rather than an omission.
        //
        // EF decides whether to include a property in an INSERT by comparing it to a sentinel, and
        // the sentinel for a non-nullable bool is false - the CLR default. While this property
        // declared HasDefaultValueSql("true"), an entity with IsActive = false was left OUT of the
        // statement and the row came back ACTIVE: a retired category was silently impossible to
        // insert. That is what EF's "configured with a database-generated default, but has no
        // configured sentinel value" warning, logged on every boot of this service, was pointing at.
        //
        // HasSentinel(null) is the documented remedy and does not apply here: EF 10 refuses it on a
        // non-nullable value type ("The sentinel value 'null' is not assignable to the property
        // 'FeedbackType.IsActive' of type 'bool'") and the context cannot even be constructed. So
        // the model stops claiming a default it must never act on; db/0011 keeps the column's
        // DEFAULT true, where it belongs - it is there for the hand-written seed, not for EF.
        // db/README.md records the class of difference.

        builder.Property(x => x.SortOrder).HasDefaultValueSql("0");
        builder.Property(x => x.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(x => x.UpdatedAt).HasDefaultValueSql("now()");
    }
}
