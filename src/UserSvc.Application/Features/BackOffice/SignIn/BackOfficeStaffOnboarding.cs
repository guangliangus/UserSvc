using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;

namespace UserSvc.Application.Features.BackOffice.SignIn;

/// <summary>
/// Which back-office account a verified employee number belongs to, and how the HR record is kept
/// on it.
/// <para>
/// <b>Matching starts at the employee number and only then falls back to the mailbox.</b> The
/// employee number is HR's own key and survives a rename, a transfer and a change of address,
/// while the mailbox does not - so matching on the address first would give one person a second
/// account the first time corporate mail moved them to a new domain. The mailbox fallback exists
/// for the staff member who already has an account from the password door and is signing in with
/// a one-time password for the first time; that case links the employee number onto the account
/// that already exists rather than creating a rival.
/// </para>
/// </summary>
public sealed class BackOfficeStaffOnboarding(
    IBackendUserRepository users,
    IBackendIdentityRepository identities,
    IdentifierProtector protector,
    IUnitOfWork unitOfWork,
    IClock clock,
    ILogger<BackOfficeStaffOnboarding> logger)
{
    /// <summary>Stamped on rows this flow writes. There is no acting operator - the person signing
    /// in is the subject, not the author of an administrative change.</summary>
    private const string SystemActor = "system";

    /// <summary>
    /// The account behind an employee number, provisioning one from the HR record when there is
    /// none.
    /// </summary>
    public async Task<StaffAccountResolution> ResolveAsync(
        string staffId,
        string email,
        StaffProfile profile,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(staffId);
        ArgumentNullException.ThrowIfNull(profile);

        if (await FindByOtpAsync(staffId, cancellationToken) is { } byStaffCode)
        {
            return new StaffAccountResolution(byStaffCode, NeedsOtpIdentity: false, CanSave: true);
        }

        if (await FindByEmailAsync(email, cancellationToken) is { } byEmail)
        {
            // The employee number is not linked to this account yet. Linking it is the caller's
            // next step, so the whole sign-in stages one save rather than two.
            return new StaffAccountResolution(byEmail, NeedsOtpIdentity: true, CanSave: true);
        }

        return await ProvisionAsync(staffId, email, profile, cancellationToken);
    }

    /// <summary>
    /// Stages the employee-number identity for an account that did not have one.
    /// <para>
    /// An employee number already linked to <b>another</b> account is a refusal and not a
    /// re-link: the two accounts would then both claim to be the same employee, and whichever the
    /// next sign-in happened to resolve would decide whose roles that person holds. It needs a
    /// human to say which of the two is the real one.
    /// </para>
    /// </summary>
    /// <exception cref="ConflictException">The employee number belongs to a different account.</exception>
    public async Task EnsureOtpIdentityAsync(
        BackendUser account, string staffId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(account);

        var existing = await FindOtpIdentityAsync(staffId, cancellationToken);

        if (existing is not null)
        {
            if (existing.UserId == account.Id)
            {
                return;
            }

            logger.LogError(
                "Employee number identity {IdentityId} already belongs to back-office account "
                + "{OwningUserId}, but the staff directory just authenticated it for account "
                + "{SigningInUserId}. One of the two accounts is a duplicate and a person has to "
                + "decide which.",
                existing.Id,
                existing.UserId,
                account.Id);

            throw new ConflictException(
                ErrorCodes.StaffCodeConflict,
                "This employee number is already linked to another back-office account.");
        }

        identities.Add(BuildIdentity(account.Id, BackendIdentityTypes.Otp, staffId, clock.UtcNow));
    }

    /// <summary>
    /// Brings the HR-owned fields on the account up to date and reports whether anything moved.
    /// <para>
    /// <b>HR is the system of record for these five fields</b>, so an upstream rename or transfer
    /// wins over whatever the row holds and lands at the next one-time-password sign-in.
    /// </para>
    /// <para>
    /// <b>An empty upstream value means "HR sent nothing", never "clear it".</b> A blank name would
    /// render as an empty row on every screen that lists people, and a blank department would
    /// silently drop the label an operator uses to find their own team - so a missing field is
    /// skipped rather than written. That also keeps the write small: only fields that actually
    /// differ are touched, so a sign-in by somebody whose record has not changed is a read.
    /// </para>
    /// </summary>
    public bool SyncStaffProfile(BackendUser account, string staffId, StaffProfile profile)
    {
        ArgumentNullException.ThrowIfNull(account);
        ArgumentNullException.ThrowIfNull(profile);

        var (first, last) = BackOfficeNames.SplitFullName(profile.FullName);

        var changed = Apply(account.StaffCode, staffId, value => account.StaffCode = value)
                      | Apply(account.FirstName, first, value => account.FirstName = value)
                      | Apply(account.LastName, last, value => account.LastName = value)
                      | Apply(account.Nickname, profile.Alias, value => account.Nickname = value)
                      | Apply(account.DeptNo, profile.DepartmentNo, value => account.DeptNo = value)
                      | Apply(account.DeptName, profile.DepartmentName, value => account.DeptName = value);

        if (changed)
        {
            account.UpdatedAt = clock.UtcNow;
            account.UpdatedBy = SystemActor;
        }

        return changed;
    }

    /// <summary>
    /// Creates an account from the HR record, with both its identities, in one insert.
    /// <para>
    /// It starts <b>ACTIVE and password-less</b>, which is the one place in this service where an
    /// account is created already activated. That is deliberate: the corporate directory has just
    /// authenticated this person as current staff, which is the same evidence an administrator
    /// would activate them on, and an account created PENDING would sign in with no authority and
    /// no way for its holder to tell why. Password-less because there is nothing to set one from -
    /// the local password door opens later, through registration, if they ever want it.
    /// </para>
    /// <para>
    /// A concurrent first sign-in for the same person is the expected failure here, not a
    /// surprise: two devices, two requests, both looked and found nothing. The loser re-resolves
    /// and uses the row the winner committed. <b>Its unit of work is poisoned by then</b> - the
    /// rejected insert is still tracked, and any later save would retry it - so the resolution
    /// says so and the caller does no further writing on this request.
    /// </para>
    /// </summary>
    private async Task<StaffAccountResolution> ProvisionAsync(
        string staffId,
        string email,
        StaffProfile profile,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        var (first, last) = BackOfficeNames.SplitFullName(profile.FullName);
        var alias = profile.Alias.Trim();
        var handle = alias.Length > 0 ? alias : BackOfficeNames.EmailLocalPart(email);

        var account = new BackendUser
        {
            // No password hash: this account has no local password door yet, and null is the
            // honest way to say so - it is what HasPassword() reads.
            PasswordHash = null,
            FirstName = first,
            LastName = last,
            Nickname = handle.Length > 0 ? handle : BackOfficeIdentifiers.GenerateHandle(),
            StaffCode = staffId,
            DeptNo = profile.DepartmentNo.Trim(),
            DeptName = profile.DepartmentName.Trim(),
            Status = BackendUserStatuses.Active,
            Origin = BackendUserOrigins.Internal,
            CreatedAt = now,
            UpdatedAt = now,
            CreatedBy = SystemActor,
            UpdatedBy = SystemActor,
        };

        // Attached to the graph rather than inserted separately, so EF fills user_id from the key
        // the account insert generates instead of needing a second round trip.
        account.Identities.Add(BuildIdentity(0, BackendIdentityTypes.Email, email, now));
        account.Identities.Add(BuildIdentity(0, BackendIdentityTypes.Otp, staffId, now));

        users.Add(account);

        try
        {
            await unitOfWork.SaveChangesAsync(cancellationToken);

            logger.LogInformation(
                "Provisioned back-office account {BackendUserId} from the staff directory on first "
                + "one-time-password sign-in.",
                account.Id);

            return new StaffAccountResolution(account, NeedsOtpIdentity: false, CanSave: true);
        }
        catch (ConflictException ex) when (ex.ErrorCode == ErrorCodes.Conflict)
        {
            logger.LogInformation(
                ex,
                "A concurrent first sign-in provisioned this staff member between the lookup and "
                + "the insert; using the committed account instead.");

            var winner = await FindByOtpAsync(staffId, cancellationToken);
            if (winner is not null)
            {
                return new StaffAccountResolution(winner, NeedsOtpIdentity: false, CanSave: false);
            }

            // The insert lost on the mailbox index rather than on the employee number, so whichever
            // account won the race still needs the employee number linked to it - and this unit of
            // work can no longer write anything. Refusing beats signing somebody in against an
            // account whose employee number points at a different person.
            throw new ConflictException(
                ErrorCodes.StaffCodeConflict,
                "This staff member's account is being created by another request. "
                + "Try signing in again.",
                ex);
        }
    }

    private async Task<BackendUser?> FindByOtpAsync(string staffId, CancellationToken cancellationToken)
    {
        var identity = await FindOtpIdentityAsync(staffId, cancellationToken);

        return identity is null ? null : await LoadAsync(identity, cancellationToken);
    }

    private async Task<BackendUser?> FindByEmailAsync(string email, CancellationToken cancellationToken)
    {
        var identity = await identities.FindActiveAsync(
            BackendIdentityTypes.Email, HashOf(BackendIdentityTypes.Email, email), cancellationToken);

        return identity is null ? null : await LoadAsync(identity, cancellationToken);
    }

    private Task<BackendIdentity?> FindOtpIdentityAsync(string staffId, CancellationToken cancellationToken) =>
        identities.FindActiveAsync(
            BackendIdentityTypes.Otp, HashOf(BackendIdentityTypes.Otp, staffId), cancellationToken);

    /// <summary>
    /// Loads the account an identity points at. A dangling identity is a 500 rather than a sign-in
    /// refusal: the row cannot exist without a cascade having failed, and answering "wrong code"
    /// would hide a broken database behind a message about the operator's own typing.
    /// </summary>
    private async Task<BackendUser> LoadAsync(BackendIdentity identity, CancellationToken cancellationToken)
    {
        var account = await users.FindByIdAsync(identity.UserId, cancellationToken);
        if (account is not null)
        {
            return account;
        }

        logger.LogError(
            "Back-office identity {IdentityId} points at account {BackendUserId}, which does not "
            + "exist. The foreign key on iam.backend_identities makes this impossible unless the "
            + "row was written around it.",
            identity.Id,
            identity.UserId);

        throw new AppException(
            ErrorCodes.InternalError, "This account's login identity is inconsistent.", 500);
    }

    private BackendIdentity BuildIdentity(
        int userId, string identityType, string identifier, DateTimeOffset now)
    {
        var normalized = BackOfficeIdentifiers.Normalize(identityType, identifier);

        return new BackendIdentity
        {
            UserId = userId,
            IdentityType = identityType,
            IdentifierHash = protector.Hash(normalized),
            IdentifierCiphertext = protector.Encrypt(normalized),
            IdentifierMasked = BackOfficeIdentifiers.Mask(identityType, normalized),
            KeyVersion = protector.KeyVersion,
            Status = BackendIdentityStatuses.Active,
            CreatedAt = now,
            UpdatedAt = now,
            CreatedBy = SystemActor,
            UpdatedBy = SystemActor,
        };
    }

    private string HashOf(string identityType, string identifier) =>
        protector.Hash(BackOfficeIdentifiers.Normalize(identityType, identifier));

    /// <summary>
    /// Writes <paramref name="incoming"/> onto the account only when HR actually sent it and it
    /// differs from what is there. Returns whether it wrote.
    /// </summary>
    private static bool Apply(string? current, string? incoming, Action<string> write)
    {
        var value = (incoming ?? string.Empty).Trim();
        if (value.Length == 0 || string.Equals(value, current, StringComparison.Ordinal))
        {
            return false;
        }

        write(value);
        return true;
    }
}

/// <summary>
/// Which account a one-time-password sign-in resolved to, and what the caller may still do with
/// the unit of work.
/// </summary>
/// <param name="Account">The account, tracked so the caller can update it.</param>
/// <param name="NeedsOtpIdentity">Whether the employee number still has to be linked to it.</param>
/// <param name="CanSave">
/// False after a lost provisioning race. The rejected insert is still tracked in this unit of
/// work, so any further save would retry it and fail again - the caller must sign the operator in
/// without writing anything else on this request. What it loses is a last-seen timestamp and one
/// staff-profile refresh, both of which land at the next sign-in.
/// </param>
public sealed record StaffAccountResolution(BackendUser Account, bool NeedsOtpIdentity, bool CanSave);
