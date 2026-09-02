using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Auth;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps <see cref="UserPasskey"/> onto <c>identity.user_passkeys</c>.
/// <para>
/// <b>Three column types here are not the house defaults, and all three come from the live
/// schema rather than from preference.</b> <c>credential_id</c> and <c>public_key</c> are
/// <c>bytea</c> because they are raw binary that nothing ever reads as text - base64 in a
/// <c>text</c> column would cost a third more space and an encode on every comparison.
/// <c>transports</c> is <c>jsonb</c> because it is a list whose members the browser defines and we
/// only pass through. <c>attestation_type</c> is <c>varchar(20)</c>, the one length-constrained
/// string column in this schema; it is kept as the live database has it rather than widened to
/// <c>text</c>, because widening a column the Go service still writes to is a change to a shared
/// table, not a tidy-up.
/// </para>
/// <para>
/// No <c>xmin</c> concurrency token. Optimistic concurrency guards a read-modify-write, and the one
/// contended write here - advancing the signature counter - is not one that a 409 would help with:
/// two concurrent assertions for the same credential mean the credential is being used twice at
/// once, which the counter check itself is there to catch. A concurrency token would turn that
/// into "please retry", which is precisely the wrong advice.
/// </para>
/// </summary>
public sealed class UserPasskeyConfiguration : IEntityTypeConfiguration<UserPasskey>
{
    public void Configure(EntityTypeBuilder<UserPasskey> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("user_passkeys");
        builder.HasKey(x => x.Id);

        builder.Property(x => x.CredentialId).HasColumnType("bytea").IsRequired();
        builder.Property(x => x.PublicKey).HasColumnType("bytea").IsRequired();
        builder.Property(x => x.Aaguid).HasColumnType("bytea");

        builder.Property(x => x.SignCount).HasDefaultValue(0L);
        builder.Property(x => x.Transports).HasColumnType("jsonb").IsRequired().HasDefaultValue("[]");
        builder.Property(x => x.AttestationType).HasMaxLength(20).IsRequired().HasDefaultValue("none");
        builder.Property(x => x.BackupEligible).HasDefaultValue(false);
        builder.Property(x => x.BackupState).HasDefaultValue(false);
        builder.Property(x => x.Name).HasMaxLength(UserPasskey.MaxNameLength);

        // A discoverable login arrives with nothing but this value, so the lookup on it is the hot
        // path of the whole slice - and it must be unique service-wide, not per user: two accounts
        // claiming one credential id would make that lookup ambiguous at the exact moment nobody
        // has said who they are yet.
        builder.HasIndex(x => x.CredentialId).IsUnique();

        // Listing an account's credentials, and building the allow-list for an identifier-scoped
        // login.
        builder.HasIndex(x => x.UserId);

        // The foreign key to identity.users is declared in the DDL and deliberately not modelled
        // here: there is no navigation in either direction (a passkey is not part of the User
        // aggregate), and giving EF the relationship purely to emit a constraint would rename the
        // one the live database already has.
    }
}
