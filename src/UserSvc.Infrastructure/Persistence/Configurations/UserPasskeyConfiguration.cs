using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Users;

namespace UserSvc.Infrastructure.Persistence.Configurations;

/// <summary>
/// Maps <see cref="UserPasskey"/> onto <c>identity.user_passkeys</c>.
/// <para>
/// <b>Two column types here are not the house default of <c>text</c>, and both earn it.</b>
/// <c>credential_id</c> and <c>public_key</c> are <c>bytea</c> because they are raw binary that
/// nothing ever reads as text - base64 in a <c>text</c> column would cost a third more space and an
/// encode on every comparison. <c>transports</c> is <c>jsonb</c> because it is a list whose members
/// the browser defines and we only pass through.
/// </para>
/// <para>
/// <c>attestation_type</c> and <c>name</c> used to be <c>varchar(20)</c> and <c>varchar(100)</c>,
/// on the grounds that "widening a column the Go service still writes to is a change to a shared
/// table". Nothing is shared: this is <c>identity.user_passkeys</c>, created by <c>db/0009</c> and
/// written by this service alone, and the Go service's table is <c>uam.user_passkeys</c>, which
/// held no rows at all. Both are <c>text</c>, with the label's length checked in code
/// (<see cref="UserPasskey.MaxNameLength"/>).
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
        builder.Property(x => x.AttestationType).IsRequired().HasDefaultValue("none");
        builder.Property(x => x.BackupEligible).HasDefaultValue(false);
        builder.Property(x => x.BackupState).HasDefaultValue(false);

        // A discoverable login arrives with nothing but this value, so the lookup on it is the hot
        // path of the whole slice - and it must be unique service-wide, not per user: two accounts
        // claiming one credential id would make that lookup ambiguous at the exact moment nobody
        // has said who they are yet.
        builder.HasIndex(x => x.CredentialId).IsUnique();

        // Listing an account's credentials, and building the allow-list for an identifier-scoped
        // login.
        builder.HasIndex(x => x.UserId);

        // The foreign key to identity.users, under the name the DDL and the live database give it.
        //
        // It used to be left out of the model on the grounds that modelling it "purely to emit a
        // constraint would rename the one the live database already has" - HasConstraintName is the
        // answer to that, and it is what FeedbackConfiguration already does for the same shape. The
        // cost of leaving it out was real: a database created from the model alone had no key here
        // at all, so a passkey could name a user id that did not exist, which is the one thing a
        // credential lookup must never resolve into. RESTRICT matches the DDL and is never
        // exercised - user rows are only ever soft-deleted.
        //
        // No navigation in either direction: a passkey is not part of the User aggregate, and
        // WithMany() without a property keeps it that way.
        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(x => x.UserId)
            .OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("user_passkeys_user_id_fkey");
    }
}
