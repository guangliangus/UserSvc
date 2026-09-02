using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;

// Two slices each named a BackOfficeNames helper; this file wants the account slice's, which is
// the one that knows how to normalize a handle and split an address.
using BackOfficeNames = UserSvc.Application.Features.BackOffice.Accounts.BackOfficeNames;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// Finds or creates the back-office account a membership will hang off.
/// <para>
/// It does <b>not</b> go through <c>BackOfficeAccountAppService.RegisterAsync</c>, and could not:
/// that path is self-service and spends a verification ticket proving the caller controls the
/// mailbox. Here an administrator is opening an account on somebody else's behalf, so there is no
/// ticket and no proof - which is exactly why the account is created with a one-time password that
/// only ever leaves the system by e-mail. The row shape below is otherwise identical to that
/// path's, deliberately: two ways to write <c>iam.backend_users</c> that disagree about defaults is
/// how a directory ends up with rows nothing can sign in as.
/// </para>
/// <para>
/// <b>No e-mail is sent from here.</b> This runs inside the caller's transaction, which holds the
/// tenant advisory lock; sending would stretch that lock across an HTTP call and could post
/// credentials for an account a rollback then un-creates. The caller sends after the commit.
/// </para>
/// </summary>
public sealed class BackOfficeUserProvisioner(
    IBackendUserRepository users,
    IBackendIdentityRepository identities,
    IdentifierProtector protector,
    PasswordHasher passwordHasher,
    IUnitOfWork unitOfWork,
    IClock clock) : IBackOfficeUserProvisioner
{
    private const string SystemActor = "system";

    public async Task<ProvisionedTarget> ResolveOrProvisionAsync(
        int userId, NewAccountRequest? newAccount, CancellationToken cancellationToken)
    {
        if (userId > 0)
        {
            // A named target that does not exist is the administrator's mistake, not a reason to
            // create an account they did not ask for.
            _ = await users.ReadByIdAsync(userId, cancellationToken)
                ?? throw new BadRequestException(
                    ErrorCodes.MemberNotFound, "The target user does not exist.");

            return new ProvisionedTarget(userId, ReusedAccount: true, InitialPassword: string.Empty);
        }

        ArgumentNullException.ThrowIfNull(newAccount);

        var normalizedEmail = BackOfficeIdentifiers.Normalize(BackendIdentityTypes.Email, newAccount.Email);
        var emailHash = protector.Hash(normalizedEmail);

        var existing = await identities.FindActiveAsync(
            BackendIdentityTypes.Email, emailHash, cancellationToken);

        if (existing is not null)
        {
            // The address is already somebody's. Reusing the account is the right answer - the
            // person exists and is being given access to one more tenant - and it is also the only
            // safe one: creating a second account for the same mailbox would let either of them
            // reset the other's password.
            return new ProvisionedTarget(existing.UserId, ReusedAccount: true, InitialPassword: string.Empty);
        }

        var password = InitialPasswordGenerator.Generate();
        var now = clock.UtcNow;
        var handle = BackOfficeNames.NormalizeNickname(newAccount.Nickname);
        if (handle.Length == 0)
        {
            handle = BackOfficeNames.EmailLocalPart(normalizedEmail);
        }

        var account = new BackendUser
        {
            PasswordHash = passwordHasher.Hash(password),
            FirstName = newAccount.FirstName.Trim(),
            LastName = newAccount.LastName.Trim(),

            // A blank display name renders as an empty row on every screen that lists people.
            Nickname = handle.Length > 0 ? handle : BackOfficeIdentifiers.GenerateHandle(),

            // ACTIVE, not PENDING: the self-service path leaves an account pending until the person
            // finishes onboarding, but this one was opened by an administrator who has just granted
            // it a membership. A pending account would hold that membership and be unable to use it.
            Status = BackendUserStatuses.Active,

            // EXTERNAL is what makes the administrator-driven password reset legal for this account
            // later on; an INTERNAL account has no local password to reset.
            Origin = BackendUserOrigins.External,
            CreatedAt = now,
            UpdatedAt = now,
            CreatedBy = SystemActor,
            UpdatedBy = SystemActor,
        };

        account.Identities.Add(new BackendIdentity
        {
            IdentityType = BackendIdentityTypes.Email,
            IdentifierHash = emailHash,
            IdentifierCiphertext = protector.Encrypt(normalizedEmail),
            IdentifierMasked = BackOfficeIdentifiers.Mask(BackendIdentityTypes.Email, normalizedEmail),
            KeyVersion = protector.KeyVersion,
            Status = BackendIdentityStatuses.Active,
            CreatedAt = now,
            UpdatedAt = now,
            CreatedBy = SystemActor,
            UpdatedBy = SystemActor,
        });

        users.Add(account);

        // Flushed, not committed. The caller's transaction is still open and still owns the
        // commit; this only makes the database assign the identity, because the membership row
        // written a few lines later in that same transaction has to point at it.
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return new ProvisionedTarget(account.Id, ReusedAccount: false, InitialPassword: password);
    }
}
