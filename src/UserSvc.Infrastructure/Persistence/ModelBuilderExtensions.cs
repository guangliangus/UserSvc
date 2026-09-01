using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace UserSvc.Infrastructure.Persistence;

public static class ModelBuilderExtensions
{
    /// <summary>
    /// Uses PostgreSQL's <c>xmin</c> system column as an optimistic concurrency token: no schema
    /// change, no business code. When two writers race the same row, the later SaveChanges throws
    /// <c>DbUpdateConcurrencyException</c>, which the API maps to 409 so the client re-reads and
    /// retries (decision 15).
    /// </summary>
    public static EntityTypeBuilder<T> UseXminConcurrencyToken<T>(this EntityTypeBuilder<T> builder)
        where T : class
    {
        builder.Property<uint>("xmin")
            .HasColumnName("xmin")
            .HasColumnType("xid")
            .ValueGeneratedOnAddOrUpdate()
            .IsConcurrencyToken();

        return builder;
    }
}
