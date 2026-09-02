using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Users;

namespace UserSvc.Infrastructure.Persistence.Configurations;

public sealed class UserIdentityConfiguration : IEntityTypeConfiguration<UserIdentity>
{
    public void Configure(EntityTypeBuilder<UserIdentity> builder)
    {
        builder.ToTable("user_identities");
        builder.HasKey(x => x.Id);
        builder.UseXminConcurrencyToken();
        builder.HasQueryFilter(x => x.Status != UserStatuses.Deleted);

        // "Unique but revocable" via a partial unique index — once unbound, the same phone
        // number can be attached to a different account.
        builder.HasIndex(x => new { x.IdentityType, x.IdentifierHash })
            .IsUnique()
            .HasFilter($"status = '{UserStatuses.Active}'");

        // jsonb rather than json: stored parsed, so a future query that does need to reach inside
        // can be indexed. The naming convention gives us the column name; only the type needs saying.
        builder.Property(x => x.ProviderDetails).HasColumnType("jsonb");

        // One active provider identity per (type, provider, subject). The blind index above cannot
        // carry this: it is keyed on the hashed identifier, and for Firebase the identifier is the
        // uid, which changes when Firebase re-creates its user record for the same third-party
        // account. Filtered to rows that actually have a subject, so phone and email identities -
        // which have neither - do not all collide on ('', '').
        builder.HasIndex(x => new { x.IdentityType, x.Provider, x.ProviderUid })
            .IsUnique()
            .HasFilter($"status = '{UserStatuses.Active}' AND provider_uid <> ''");

        // The unification lookup: given a WeChat union id, find the earliest active WeChat-family
        // identity. Not unique - one human legitimately holds one row per WeChat application.
        builder.HasIndex(x => x.ProviderUid)
            .HasFilter("provider_uid <> ''");

        builder.HasIndex(x => x.UserId);
    }
}
