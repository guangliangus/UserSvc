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

        // Deliberately NOT indexed: authorization_id. The traffic runs the other way - a session is
        // found by its sid and hands its authorization id to OpenIddict - so an index on it would
        // be write cost on every sign-in for a lookup no code performs.
    }
}
