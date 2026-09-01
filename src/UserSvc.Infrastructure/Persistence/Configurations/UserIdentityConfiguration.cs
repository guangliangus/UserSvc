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

        builder.HasIndex(x => x.UserId);
    }
}
