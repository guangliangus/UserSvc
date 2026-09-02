using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Verification;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Iam;
using UserSvc.Domain.Verification;

namespace UserSvc.Application.Features.BackOffice.Accounts;

/// <summary>
/// Back-office account use cases that need nothing but this service's own tables: registering a
/// corporate mailbox, resetting a back-office password, and reading the operator directory.
/// <para>
/// <b>Registering does not sign anyone in</b>, exactly as on the consumer plane: token issuance
/// belongs to the authentication endpoints, and a second place that mints credentials is a second
/// definition of what a session is.
/// </para>
/// <para>
/// <b>Visibility is a parameter, never something this service derives.</b> Every directory method
/// takes a <see cref="UserVisibilityFilter"/> resolved from the caller's authority by the tenant
/// module, and the three states are not interchangeable: <c>null</c> means unrestricted and belongs
/// to the platform super administrator alone, while
/// <see cref="UserVisibilityFilter.Nothing"/> means "administers nothing" and matches no account.
/// A caller that cannot resolve authority must pass <see cref="UserVisibilityFilter.Nothing"/> -
/// passing <c>null</c> hands over the whole platform.
/// </para>
/// </summary>
public sealed class BackOfficeAccountAppService(
    IBackendUserRepository users,
    IBackendIdentityRepository identities,
    IVerificationTicketConsumer tickets,
    BackOfficeResetTargetGate resetTargets,
    IIamAuditLogRepository auditLog,
    IdentifierProtector protector,
    PasswordHasher passwordHasher,
    IUnitOfWork unitOfWork,
    IClock clock,
    IOptions<BackOfficeAccountOptions> options,
    ILogger<BackOfficeAccountAppService> logger)
{
    private readonly BackOfficeAccountOptions _options = options.Value;

    /// <summary>
    /// Registers a corporate mailbox as a back-office account, or attaches a password to the
    /// account that mailbox already has.
    /// <para>
    /// <b>Link first, then create.</b> Staff who signed in through the corporate one-time-password
    /// path already have an account with no local password; for them this call sets one rather than
    /// refusing as a duplicate. An account that already has a password is the real duplicate, and
    /// only that is refused.
    /// </para>
    /// <para>
    /// The domain gate runs before anything else. Registration is closed to non-corporate addresses
    /// for every origin - unlike sign-in, which exempts external partners - so checking it first
    /// avoids spending a verification ticket on a request that was never going to succeed.
    /// </para>
    /// </summary>
    public async Task<BackOfficeRegisterResponse> RegisterAsync(
        BackOfficeRegisterRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var allowedDomains = BackOfficeNames.InternalDomains(_options.InternalDomains);
        if (!BackOfficeNames.EmailInDomains(request.Email, allowedDomains))
        {
            // The allow-list is named in the message on purpose: the client renders it, and it is
            // configuration rather than a secret. It says nothing about any account.
            throw new ForbiddenException(
                ErrorCodes.InvalidDomain,
                "A back-office account can only be registered with a corporate email address "
                + $"({string.Join(", ", allowedDomains)}).");
        }

        var normalizedEmail = BackOfficeIdentifiers.Normalize(BackendIdentityTypes.Email, request.Email);
        var emailHash = protector.Hash(normalizedEmail);
        var now = clock.UtcNow;

        // Assigned inside the transaction body and read after it commits. The execution strategy
        // may replay that body, so everything it creates is created once and reused - a second
        // BackendUser would be tracked alongside the first and insert two rows.
        BackendUser? account = null;

        try
        {
            await unitOfWork.ExecuteInTransactionAsync(
                async ct =>
                {
                    // (1) Spend the ticket first, and inside the transaction.
                    //
                    // Inside, because consuming it is the moment the proof of mailbox control is
                    // spent: if the write below fails, the consumption rolls back with it and the
                    // caller may retry with the same ticket rather than walking the whole code flow
                    // again.
                    //
                    // First, because everything after it either costs real CPU or tells the caller
                    // something about an account, and this endpoint is anonymous.
                    //
                    // The target is the address AS TYPED, not the normalized form: the ticket was
                    // minted against the literal string the client sent to the send-code endpoint,
                    // and the two hashing rules are deliberately different.
                    if (!await tickets.TryConsumeAsync(
                            request.Email, VerificationPurposes.BackOfficeAuth, request.VerificationTicket, ct))
                    {
                        throw new BadRequestException(
                            ErrorCodes.VerificationFailed,
                            "The verification ticket is invalid, expired or already used.");
                    }

                    var existing = await identities.FindActiveAsync(
                        BackendIdentityTypes.Email, emailHash, ct);

                    if (existing is not null)
                    {
                        account = await LinkPasswordAsync(existing, request, now, ct);
                    }
                    else
                    {
                        // (2) The hash is derived here rather than before the transaction.
                        //
                        // Argon2id costs about 30 ms of CPU and holds 19 MiB while it runs, which
                        // would be the cheapest amplification target in the service if an anonymous
                        // caller could trigger it with a junk ticket. Paying for it inside an open
                        // transaction is the better side of that trade: the only row locked so far
                        // is the ticket's own, and nothing but a replay of that same ticket
                        // contends for it.
                        account ??= BuildAccount(request, normalizedEmail, emailHash, now);
                        users.Add(account);
                    }

                    await unitOfWork.SaveChangesAsync(ct);
                },
                cancellationToken);
        }
        catch (ConflictException ex) when (ex.ErrorCode == ErrorCodes.Conflict)
        {
            // Someone registered the same address between the lookup above and this insert. The
            // only unique index this statement can violate is the one on an ACTIVE email identity,
            // so the constraint name is not worth parsing - but the generic CONFLICT code is worth
            // replacing, because a lost race and a plain duplicate call for the same client
            // reaction.
            logger.LogInformation(
                ex, "A concurrent back-office registration won the race for this address.");

            throw new ConflictException(
                ErrorCodes.AlreadyRegistered,
                "This email address already has a back-office account.",
                ex);
        }

        var registered = account ?? throw new InvalidOperationException(
            "The back-office registration transaction committed without an account.");

        return new BackOfficeRegisterResponse { Id = registered.Id, Status = registered.Status };
    }

    /// <summary>
    /// Replaces a back-office password for someone who has proved control of the account's mailbox.
    /// <para>
    /// Open to both origins. An external partner resets the password they sign in with; internal
    /// staff set or reset the local password of the email door, which still sits behind the
    /// corporate domain gate at sign-in. It is not the administrator-driven reset, which is a
    /// takeover by another person and carries its own rules.
    /// </para>
    /// <para>
    /// <b>Spending the ticket and writing the password are one transaction.</b> Either the ticket is
    /// burned and the password changed, or neither happened - a ticket consumed without a password
    /// change would send the user back through the whole code flow, and a password changed without
    /// consuming the ticket would leave a replayable credential behind.
    /// </para>
    /// <para>
    /// Every access token the account holds dies with the old password, through the token-version
    /// bump in the same transaction.
    /// </para>
    /// </summary>
    public async Task ResetPasswordAsync(
        BackOfficePasswordResetRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Captured from inside the transaction so the audit entry, which is written after the
        // commit, names the account the reset actually landed on.
        BackendUser? reset = null;

        await unitOfWork.ExecuteInTransactionAsync(
            async ct =>
            {
                if (!await tickets.TryConsumeAsync(
                        request.Email, VerificationPurposes.BackOfficeResetPassword, request.VerificationTicket, ct))
                {
                    throw new BadRequestException(
                        ErrorCodes.VerificationFailed,
                        "The verification ticket is invalid, expired or already used.");
                }

                // The same gate the send-code step ran, repeated because the account may have been
                // disabled in the minutes between the code being mailed and the ticket being spent.
                var account = await resetTargets.ResolveAsync(request.Email, ct);

                var hashed = passwordHasher.Hash(request.NewPassword);

                if (!await users.UpdatePasswordHashAsync(account.Id, hashed, SystemActor, ct))
                {
                    // The row was read moments ago in this same transaction, so it cannot be gone.
                    // Failing loudly beats reporting success on a password that was not written.
                    throw new AppException(
                        ErrorCodes.InternalError, "The password could not be updated.", 500);
                }

                // Same transaction as the password write: a bump that committed without the new
                // password would sign everyone out for nothing, and a password that committed
                // without the bump would leave the old sessions alive behind a 200.
                await users.IncrementTokenVersionAsync([account.Id], ct);

                reset = account;
            },
            cancellationToken);

        logger.LogInformation(
            "Back-office account {BackendUserId} reset its own password; token version bumped.",
            reset!.Id);

        await WriteSelfPasswordResetAuditAsync(reset, cancellationToken);
    }

    /// <summary>
    /// Records the reset in the IAM audit trail, <b>after the transaction has committed and always
    /// best effort</b>.
    /// <para>
    /// Two departures from the service being replaced, and both are forced by PostgreSQL rather
    /// than chosen. It runs <i>after</i> the commit because a failed INSERT inside a transaction
    /// aborts that transaction: a swallowed audit failure would take the password change down with
    /// it, which is the opposite of best effort. And the failure is swallowed because the change has
    /// already committed - throwing here would tell a user their reset did not happen while their
    /// new password works, and they would spend the next hour typing the old one.
    /// </para>
    /// <para>
    /// The narrow window this opens - committed reset, no audit row - is why the failure is logged
    /// at Error with the account id: it is a real gap in the trail and somebody has to know.
    /// </para>
    /// </summary>
    private async Task WriteSelfPasswordResetAuditAsync(
        BackendUser account,
        CancellationToken cancellationToken)
    {
        var entry = new IamAuditLog
        {
            // Actor and target are the same account. This is the person proving control of their
            // own mailbox, not an administrator acting on someone else.
            ActorUserId = account.Id,
            ActorName = BackOfficeNames.DisplayName(account.FirstName, account.LastName, account.Nickname),

            // Platform-level, with no tenant code: a credential belongs to the account, not to any
            // membership it happens to hold.
            TenantType = IamAuditTenantTypes.Platform,
            TenantCode = string.Empty,
            Action = BackOfficeAuditActions.SelfPasswordReset,
            TargetType = IamAuditTargetTypes.User,
            TargetId = account.Id.ToString(CultureInfo.InvariantCulture),

            // No before/after snapshot, deliberately: the only thing that changed is a password
            // hash, and neither spelling of it belongs anywhere near an audit row.
            CreatedAt = clock.UtcNow,
        };

        try
        {
            await auditLog.AppendAsync(entry, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(
                ex,
                "The password reset of back-office account {BackendUserId} committed, but its audit "
                + "entry could not be written. The trail is missing this action.",
                account.Id);
        }
    }

    /// <summary>
    /// One page of the back-office directory, newest account first.
    /// <para>
    /// Page and page size are corrected rather than refused when they are below one: a pager that
    /// sends zero is a client defect the operator should not have to read an error about.
    /// </para>
    /// </summary>
    /// <param name="request">The page, page size and filters the client asked for.</param>
    /// <param name="visibility">See the note on the class. <c>null</c> is unrestricted.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    public async Task<BackOfficeUserListResponse> ListAsync(
        BackOfficeUserListRequest request,
        UserVisibilityFilter? visibility,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var page = request.Page <= 0 ? 1 : request.Page;
        var pageSize = request.PageSize <= 0 ? _options.DefaultPageSize : request.PageSize;

        var result = await users.ListAsync(
            new BackOfficeUserQuery(page, pageSize, request.Status, request.Search),
            visibility,
            cancellationToken);

        var emails = await PrimaryEmailsAsync(result.Users, cancellationToken);

        return new BackOfficeUserListResponse
        {
            Items =
            [
                .. result.Users.Select(user => new BackOfficeUserResponse
                {
                    Id = user.Id,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Nickname = BackOfficeNames.DisplayName(user.FirstName, user.LastName, user.Nickname),
                    Avatar = user.Avatar,
                    Email = emails.GetValueOrDefault(user.Id, string.Empty),
                    Status = user.Status,
                    StaffCode = user.StaffCode,
                    DeptName = user.DeptName,
                    Origin = user.Origin,

                    // Caller-gated by construction: only an unrestricted caller - which is to say
                    // another platform super administrator - can see who owns the platform. A
                    // tenant administrator reads false for everyone, including for accounts that
                    // do hold the flag.
                    IsSuperAdmin = visibility is null && user.IsSuperAdmin,
                    LastLoginAt = user.LastLoginAt,
                    CreatedAt = user.CreatedAt,
                })
            ],
            Total = result.Total,
            Page = page,
            PageSize = pageSize,
            TotalPages = pageSize <= 0 ? 0 : (int)Math.Ceiling(result.Total / (double)pageSize),
        };
    }

    /// <summary>
    /// The people picker behind every "assign this to someone" field.
    /// <para>
    /// <b>The visibility filter is the only confidentiality control this endpoint has</b>, because
    /// the screens that carry the picker hold no directory permission of their own - requiring one
    /// would answer 403 on a routine form field. Unfiltered, it answered name searches across every
    /// back-office account on the platform and confirmed any account's existence and display name
    /// from a bare id.
    /// </para>
    /// </summary>
    /// <param name="userId">Resolve one specific account, or 0 for a search.</param>
    /// <param name="nickname">Name fragment to search for. Ignored when
    /// <paramref name="userId"/> is positive.</param>
    /// <param name="visibility">The caller's <b>peer</b> visibility - the tenants they belong to,
    /// not the ones they administer. The question this endpoint answers is "who do I work with",
    /// and gating it on administrator standing would empty it for exactly the roles that use it.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    public async Task<IReadOnlyList<BackOfficeUserOptionResponse>> ListOptionsAsync(
        int userId,
        string? nickname,
        UserVisibilityFilter? visibility,
        CancellationToken cancellationToken)
    {
        var candidates = await users.ListOptionsAsync(userId, nickname, visibility, cancellationToken);

        return
        [
            .. candidates.Select(option => new BackOfficeUserOptionResponse
            {
                Id = option.Id,
                Nickname = BackOfficeNames.DisplayName(option.FirstName, option.LastName, option.Nickname),

                // JoinFullName rather than "first space last": a CJK name composes as family name
                // then given name with no separator, and the space makes it read as two people.
                FullName = BackOfficeNames.JoinFullName(option.FirstName, option.LastName),
            })
        ];
    }

    /// <summary>The audit stamp for a write nobody signed in for. Registration and self-service
    /// reset are anonymous by definition - the ticket is the proof, and it names no operator.</summary>
    private const string SystemActor = "system";

    /// <summary>
    /// Attaches a password to an account that already owns this address, and fills in the profile
    /// fields it is still missing.
    /// <para>
    /// Only empty fields are filled. A name already on the row was either typed by an operator or
    /// synchronized from HR, and a registration form is the weakest of the three sources - letting
    /// it overwrite the others would silently rename people at sign-up time.
    /// </para>
    /// </summary>
    private async Task<BackendUser> LinkPasswordAsync(
        BackendIdentity existing,
        BackOfficeRegisterRequest request,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var account = await users.FindByIdAsync(existing.UserId, cancellationToken);
        if (account is null)
        {
            logger.LogError(
                "Back-office identity {IdentityId} points at account {BackendUserId}, which does not exist.",
                existing.Id,
                existing.UserId);

            throw new AppException(
                ErrorCodes.InternalError, "This account could not be registered.", 500);
        }

        if (account.HasPassword())
        {
            throw new ConflictException(
                ErrorCodes.AlreadyRegistered, "This email address already has a back-office account.");
        }

        account.PasswordHash = passwordHasher.Hash(request.Password);

        if (string.IsNullOrWhiteSpace(account.FirstName) && !string.IsNullOrWhiteSpace(request.FirstName))
        {
            account.FirstName = request.FirstName.Trim();
        }

        if (string.IsNullOrWhiteSpace(account.LastName) && !string.IsNullOrWhiteSpace(request.LastName))
        {
            account.LastName = request.LastName.Trim();
        }

        if (string.IsNullOrWhiteSpace(account.Avatar) && !string.IsNullOrWhiteSpace(request.Avatar))
        {
            account.Avatar = request.Avatar.Trim();
        }

        account.UpdatedAt = now;
        account.UpdatedBy = SystemActor;

        return account;
    }

    /// <summary>
    /// Builds a brand-new back-office account and its email identity as one graph, so EF fills
    /// <c>user_id</c> from the key the insert generates.
    /// <para>
    /// The account starts PENDING and INTERNAL: proving control of a corporate mailbox creates an
    /// account, it does not activate one, and nothing about a self-service registration can make it
    /// external. It carries no super-administrator flag, and nothing on this path can give it one.
    /// </para>
    /// </summary>
    private BackendUser BuildAccount(
        BackOfficeRegisterRequest request,
        string normalizedEmail,
        string emailHash,
        DateTimeOffset now)
    {
        var handle = BackOfficeNames.EmailLocalPart(normalizedEmail);

        var account = new BackendUser
        {
            PasswordHash = passwordHasher.Hash(request.Password),
            FirstName = request.FirstName?.Trim(),
            LastName = request.LastName?.Trim(),

            // A blank display name renders as an empty row on every screen that lists people, so
            // an address with no local part falls back to a generated handle rather than to "".
            Nickname = handle.Length > 0 ? handle : BackOfficeIdentifiers.GenerateHandle(),
            Avatar = request.Avatar?.Trim(),
            Status = BackendUserStatuses.Pending,
            Origin = BackendUserOrigins.Internal,
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

        return account;
    }

    /// <summary>
    /// The plaintext address of each account in one batch read.
    /// <para>
    /// <b>An address that cannot be decrypted degrades to its mask, loudly.</b> A key rotation or an
    /// unavailable data key would otherwise blank the column for every row behind a 200, which
    /// reads to an operator as data loss rather than as an infrastructure problem - so the row
    /// shows a recognizable partial address and the log carries the account id and the key version
    /// that failed, which is what a rotation job needs to find the rows it missed.
    /// </para>
    /// <para>
    /// A failure to read the identities at all is <i>not</i> swallowed: this service fails closed on
    /// database errors, and a directory silently missing every address looks like a working page
    /// with a broken column.
    /// </para>
    /// </summary>
    private async Task<Dictionary<int, string>> PrimaryEmailsAsync(
        IReadOnlyList<BackendUser> accounts,
        CancellationToken cancellationToken)
    {
        var emails = new Dictionary<int, string>();
        if (accounts.Count == 0)
        {
            return emails;
        }

        var rows = await identities.ListActiveByUserIdsAsync(
            [.. accounts.Select(user => user.Id)], cancellationToken);

        // Ordered by id, so "the first email identity" is the same one on every page load.
        foreach (var identity in rows)
        {
            if (identity.IdentityType != BackendIdentityTypes.Email || emails.ContainsKey(identity.UserId))
            {
                continue;
            }

            emails[identity.UserId] = ReadIdentifier(identity);
        }

        return emails;
    }

    private string ReadIdentifier(BackendIdentity identity)
    {
        if (string.IsNullOrEmpty(identity.IdentifierCiphertext))
        {
            return identity.IdentifierMasked;
        }

        try
        {
            return protector.Decrypt(identity.IdentifierCiphertext);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            logger.LogError(
                ex,
                "The address of back-office account {BackendUserId} could not be decrypted "
                + "(identity {IdentityId}, key version {KeyVersion}). Falling back to the masked "
                + "value; this row needs re-encrypting.",
                identity.UserId,
                identity.Id,
                identity.KeyVersion);

            return identity.IdentifierMasked;
        }
    }
}
