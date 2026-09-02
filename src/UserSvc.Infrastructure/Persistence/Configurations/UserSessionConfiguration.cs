using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Auth;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps <see cref="UserSession"/> onto <c>identity.user_sessions</c>.
/// <para>
/// <b>The realm is half the key of everything keyed on the subject.</b> <c>user_id</c> holds an id
/// from either <c>identity.users</c> or <c>iam.backend_users</c>, which number their rows
/// independently, so every index that leads with the subject leads with <c>realm</c> first.
/// </para>
/// </summary>
public sealed class UserSessionConfiguration : IEntityTypeConfiguration<UserSession>
{
    /// <inheritdoc />
    public void Configure(EntityTypeBuilder<UserSession> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("user_sessions", table => table.HasCheckConstraint(
            "chk_user_sessions_realm",
            $"realm IN ('{SessionRealms.Consumer}', '{SessionRealms.BackOffice}')"));

        builder.HasKey(x => x.Id);
        builder.UseXminConcurrencyToken();

        // Domain events are transient and live in memory only; they are never persisted here.
        builder.Ignore(x => x.DomainEvents);

        // Realm and UserId read together. The pair is the row's subject, but only the two columns
        // are stored - there is nothing to persist for the projection over them.
        builder.Ignore(x => x.Subject);

        // Deliberately NOT filtered by realm. A sid is a server-generated GUID and this index is
        // what makes it resolve to exactly one row for both planes at once; scoping it per realm
        // would allow one sid to name two sessions and turn every by-sid lookup - refresh, replay,
        // sign-out - into an ambiguous read.
        builder.HasIndex(x => x.SessionId).IsUnique();

        // The subject's whole session history, active and revoked. Realm leads because a subject id
        // means nothing outside its realm, and because both columns are always equality predicates
        // here - realm's two distinct values cost nothing in that position and keep this index and
        // the unique one below ordered the same way.
        builder.HasIndex(x => new { x.Realm, x.UserId });

        // THE fix. One subject on one device may hold at most one active session - and "one
        // subject" is (realm, user_id). Keyed on user_id alone, consumer 100 and back-office 100
        // collided on this index from the same device id and one of the two simply could not sign
        // in, while the eviction and "sign out my other devices" paths that walk it crossed both
        // planes.
        builder.HasIndex(x => new { x.Realm, x.UserId, x.DeviceId })
            .IsUnique()
            .HasFilter($"status = '{SessionStatuses.Active}'");

        // Deliberately NOT indexed: authorization_id. The traffic runs the other way - a session is
        // found by its sid and hands its authorization id to OpenIddict - so an index on it would
        // be write cost on every sign-in for a lookup no code performs.
    }
}
