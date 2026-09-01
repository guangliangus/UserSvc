using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Auth;

namespace UserSvc.Infrastructure.Persistence.Configurations;

public sealed class UserSessionConfiguration : IEntityTypeConfiguration<UserSession>
{
    public void Configure(EntityTypeBuilder<UserSession> builder)
    {
        builder.ToTable("user_sessions");
        builder.HasKey(x => x.Id);
        builder.UseXminConcurrencyToken();

        // Domain events are transient and live in memory only; they are never persisted here.
        builder.Ignore(x => x.DomainEvents);

        builder.HasIndex(x => x.SessionId).IsUnique();
        builder.HasIndex(x => x.UserId);

        // One user on one device may hold at most one active session.
        builder.HasIndex(x => new { x.UserId, x.DeviceId })
            .IsUnique()
            .HasFilter($"status = '{SessionStatuses.Active}'");

        // Refresh looks a session up by its current hash. Indexing active rows only keeps
        // revoked rows out of the index.
        builder.HasIndex(x => x.CurrentRefreshTokenHash)
            .HasFilter($"status = '{SessionStatuses.Active}'");
    }
}
