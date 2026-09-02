using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Application.Ports.Verification;
using UserSvc.Application.Security;
using UserSvc.Domain.Users;
using UserSvc.Domain.Verification;

namespace UserSvc.Application.Features.Registration;

/// <summary>
/// Sign-up: spend a verification ticket, create the account and its first login identity.
/// <para>
/// It deliberately stops there. <b>Registering does not sign anyone in</b> - OpenIddict owns token
/// issuance (decision 10), so the client goes to the token endpoint next with the credentials it
/// just created. The Go original returned a token pair from this call; reproducing that would have
/// meant a second place that mints tokens, and the two would eventually disagree about what a
/// session is.
/// </para>
/// <para>
/// Everything that must not half-happen is inside one transaction: ticket consumption, the user
/// row, the identity row and the outbox row. A ticket that outlived a failed insert would be a
/// replayable credential, and a user row without its identity row would be an account nobody can
/// sign in to and nobody can re-register.
/// </para>
/// <para>
/// <b>The ticket is checked before anything else the caller can observe or pay for.</b> This is an
/// anonymous endpoint, so the order of the checks is the security design, not a style choice: see
/// the comments inside the transaction body for the two attacks the order closes.
/// </para>
/// </summary>
public sealed class RegistrationAppService(
    IUserRepository users,
    IUserIdentityRepository identities,
    IVerificationTicketConsumer tickets,
    IdentifierProtector protector,
    PasswordHasher passwordHasher,
    IUnitOfWork unitOfWork,
    IClock clock,
    ILogger<RegistrationAppService> logger)
{
    /// <summary>
    /// Used when the caller sends no nickname and the identifier offers nothing to derive one from
    /// - a phone number, which is not a name. The Go service localized this string from its i18n
    /// catalog; there is no catalog here yet, so it ships in English (see the deviation note).
    /// </summary>
    private const string DefaultNickname = "Lion Travel Member";

    public async Task<RegisterResponse> RegisterAsync(
        RegisterRequest request,
        CancellationToken cancellationToken)
    {
        // The controller's validation filter already rejects an unsupported identity type with a
        // field dictionary. Repeating the check here is not redundancy for its own sake: without
        // it this method's failure semantics would depend on a filter it does not own, and a
        // direct caller - a future back-office flow, a test - would get ResolveIdentityType's
        // ArgumentOutOfRangeException, which the handler can only render as a 500.
        if (!IdentifierNormalizer.IsSupportedIdentityType(request.IdentityType))
        {
            throw new BadRequestException(
                ErrorCodes.ValidationFailed,
                $"Identity type must be {IdentityTypes.Phone} or {IdentityTypes.Email}.");
        }

        var identityType = IdentifierNormalizer.ResolveIdentityType(request.IdentityType);
        var identifier = IdentifierNormalizer.Normalize(identityType, request.Identifier);

        // Normalizing a phone number keeps only its digits, so an identifier made of nothing else
        // normalizes to the empty string. Hashing that would give every such request the same
        // blind index - one account, and a unique-index collision for the second caller - so it is
        // refused here rather than stored.
        if (identifier.Length == 0)
        {
            throw new BadRequestException(
                ErrorCodes.ValidationFailed, "The identifier is required and must contain digits or an address.");
        }

        // Decision 13: the plaintext never reaches a column. The blind index is what the unique
        // index and every later lookup are built on; the ciphertext is how the value is read back.
        var identifierHash = protector.Hash(identifier);

        var now = clock.UtcNow;

        // Assigned inside the transaction body; read after it commits. Null afterwards would mean
        // the body never ran, which ExecuteInTransactionAsync does not do.
        User? created = null;

        try
        {
            await unitOfWork.ExecuteInTransactionAsync(
                async ct =>
                {
                    // (1) Spend the ticket first, and inside the transaction.
                    //
                    // Inside, because consuming it is the moment the proof of ownership is spent:
                    // if the insert below then fails, the consumption rolls back with it and the
                    // caller may retry with the same ticket until its own TTL runs out. That is
                    // the intended trade - the alternative burns a ticket on a lost race and forces
                    // the user through the whole code flow again.
                    //
                    // First, because everything after it is either expensive or informative, and
                    // this endpoint is anonymous. See (2) and (3).
                    //
                    // The target is the identifier AS THE CALLER TYPED IT, not the normalized
                    // form. VerificationHashing.HashTarget hashes over trim-and-lowercase and
                    // nothing else, so target_hash was built from the literal string sent to
                    // /verification/send - while IdentifierNormalizer drops a phone number's
                    // leading plus. Handing the consumer the normalized value would therefore miss
                    // every ticket ever minted for a number written the E.164 way, and the failure
                    // would read to the client as a bad ticket.
                    if (!await tickets.TryConsumeAsync(
                            request.Identifier, VerificationPurposes.Auth, request.VerificationTicket, ct))
                    {
                        throw new BadRequestException(
                            ErrorCodes.VerificationFailed,
                            "The verification ticket is invalid, expired or already used.");
                    }

                    // (2) Only now may the caller learn that the identifier is taken.
                    //
                    // The Go original ran this check first (spec 03 3.4.1 step 2). Under real HTTP
                    // status codes that ordering is an account-enumeration oracle: anyone could
                    // post an address with a junk ticket and read 409 ALREADY_REGISTERED for
                    // "this mailbox has an account" and 400 VERIFICATION_FAILED for "it does not".
                    // Behind the ticket, the only caller who learns it is one who has just proved
                    // control of the address, and to them it is the message they need.
                    //
                    // It stays advisory - correctness is the partial unique index below - so it
                    // does not lock, and losing the race is handled by the catch clause.
                    if (await identities.FindActiveAsync(identityType, identifierHash, ct) is not null)
                    {
                        throw new ConflictException(
                            ErrorCodes.AlreadyRegistered, "This email or phone number is already registered.");
                    }

                    // (3) Build the graph, which is where the password is hashed.
                    //
                    // Argon2id at these parameters costs ~30 ms of CPU and holds 19 MiB while it
                    // runs (see PasswordHasher). Doing it before the ticket check would hand every
                    // anonymous caller a 19 MiB memory allocation and a CPU burn for the price of
                    // one HTTP request - the cheapest amplification target in the service. Paying
                    // for it with ~30 ms of an already-open transaction is the better side of that
                    // trade: the only row locked so far is the ticket's own, which nothing but a
                    // replay of the same ticket contends for.
                    //
                    // Built once even if the execution strategy replays this body: a second User
                    // would be tracked alongside the first and insert two rows.
                    created ??= BuildUser(request, identityType, identifier, identifierHash, now);

                    // The identity rides on the user's navigation collection rather than being
                    // added separately, so EF fills user_id from the generated key in one round
                    // trip. Adding it through its own repository would need the id first, which
                    // means two SaveChanges and a wider window for the second to fail.
                    users.Add(created);
                    await unitOfWork.SaveChangesAsync(ct);
                },
                cancellationToken);
        }
        catch (ConflictException ex) when (ex.ErrorCode == ErrorCodes.Conflict)
        {
            // Someone registered the same identifier between the check above and this insert. The
            // only unique index this statement can violate is
            // (identity_type, identifier_hash) WHERE status = 'ACTIVE', so the constraint name is
            // not worth parsing - but the generic CONFLICT code is worth replacing, because the
            // client's reaction to a lost race is the same as to a plain duplicate.
            logger.LogInformation(
                ex,
                "A concurrent registration won the race for a {IdentityType} identifier; answering ALREADY_REGISTERED.",
                identityType);

            throw new ConflictException(
                ErrorCodes.AlreadyRegistered, "This email or phone number is already registered.", ex);
        }

        var user = created ?? throw new InvalidOperationException(
            "The registration transaction committed without building a user.");

        return new RegisterResponse
        {
            Id = user.Id,
            Status = user.Status,
            Nickname = user.Nickname,
            CreatedAt = user.CreatedAt,
        };
    }

    /// <summary>
    /// Builds the whole graph, including the Argon2id derivation. Called from inside the
    /// transaction and exactly once per request - see the comment at the call site for why both
    /// halves of that sentence matter.
    /// </summary>
    private User BuildUser(
        RegisterRequest request,
        string identityType,
        string identifier,
        string identifierHash,
        DateTimeOffset now)
    {
        var user = new User
        {
            // ACTIVE, not PENDING: the identifier was proved moments ago by the ticket being spent,
            // so there is nothing left for the account to be pending on.
            Status = UserStatuses.Active,
            FirstName = request.FirstName ?? string.Empty,
            LastName = request.LastName ?? string.Empty,
            Nickname = ResolveNickname(request.Nickname, identityType, identifier),
            Avatar = request.Avatar ?? string.Empty,
            PasswordAlgo = PasswordHasher.AlgorithmName,
            PasswordHash = passwordHasher.Hash(request.Password),
            CreatedAt = now,
            UpdatedAt = now,
        };

        user.Identities.Add(new UserIdentity
        {
            IdentityType = identityType,
            IdentifierHash = identifierHash,
            IdentifierCiphertext = protector.Encrypt(identifier),
            IdentifierKeyVersion = protector.KeyVersion,
            Status = UserStatuses.Active,
            CreatedAt = now,
            UpdatedAt = now,
        });

        // Decision 16: the interceptor turns this into an outbox row in the same transaction as the
        // insert. It carries the identity type and the blind index and no id, because the outbox
        // row is written before PostgreSQL assigns one - an event carrying user.Id would publish 0.
        user.RecordRegistration(identityType, identifierHash, now);

        return user;
    }

    /// <summary>
    /// Third-party name, then email local part, then the default - the Go original's precedence,
    /// minus the third-party branch, which belongs to the social-login slice that supplies a name.
    /// A phone number is not a display name, so phone sign-ups get the default.
    /// </summary>
    private static string ResolveNickname(string? requested, string identityType, string identifier)
    {
        if (!string.IsNullOrWhiteSpace(requested))
        {
            return requested.Trim();
        }

        if (identityType == IdentityTypes.Email)
        {
            var separator = identifier.IndexOf('@', StringComparison.Ordinal);
            if (separator > 0)
            {
                return identifier[..separator];
            }
        }

        return DefaultNickname;
    }
}
