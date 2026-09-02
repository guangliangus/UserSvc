using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.Auth;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Application.Security;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Users;

namespace UserSvc.Application.Features.Passkeys;

/// <summary>
/// Passkey registration, login and management.
/// <para>
/// The cryptography is not here - <see cref="IWebAuthnCeremony"/> owns it, along with the challenge
/// that spans a ceremony's two requests. What is here is everything the protocol does not decide:
/// which account a credential may be added to, what a caller is allowed to learn about credentials
/// that are not theirs, and when removing one would lock somebody out of their own account.
/// </para>
/// <para>
/// <b>Three answers in this file are deliberately vague, and each one is vague about a different
/// thing.</b> A login-begin that names an identifier we do not recognise falls through to a
/// discoverable ceremony rather than saying "no such account" - otherwise the endpoint is an
/// address checker that needs no credential at all. A read or delete aimed at somebody else's
/// credential answers 404 rather than 403, because 403 would confirm the id exists. And a login
/// whose credential we have never seen answers exactly what a login with a bad signature answers
/// as far as status goes - 401 - while still using a distinct error code, so a client can tell
/// "this device is not enrolled here" from "that did not verify" without the status line itself
/// leaking which credential ids are real.
/// </para>
/// </summary>
public sealed class PasskeyAppService(
    IUserPasskeyRepository passkeys,
    IPasskeyIdentityLink identityLink,
    IWebAuthnCeremony ceremony,
    IUserRepository users,
    IUserIdentityRepository identities,
    IRateLimiter rateLimiter,
    IdentifierProtector protector,
    IUnitOfWork unitOfWork,
    IClock clock,
    ILogger<PasskeyAppService> logger)
{
    /// <summary>
    /// The login-begin budget's dimension. Begin is cheap for the caller and not free for us - it
    /// mints a challenge and writes it to Redis - so it is the half of the login that gets a
    /// throttle. The limits are fixed rather than configurable: they are generous enough that no
    /// deployment needs to raise them, and a knob here would only ever be turned the wrong way.
    /// </summary>
    private const string LoginBeginRateLimitDimension = "passkey-login-begin-ip";

    private const int LoginBeginPerMinute = 20;
    private const int LoginBeginPerHour = 100;

    /// <summary>The bucket requests with no determinable peer address share. Named rather than
    /// blank because the limiter refuses a blank subject.</summary>
    private const string UnknownClient = "unknown-client";

    /// <summary>Start enrolling a new credential for the signed-in account.</summary>
    public async Task<PasskeyChallengeResponse> BeginRegistrationAsync(
        int userId,
        PasskeyRegisterBeginRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var user = await RequireActiveUserAsync(userId, cancellationToken);
        var existing = await passkeys.ListByUserAsync(userId, cancellationToken);

        var start = await ceremony.BeginRegistrationAsync(
            new WebAuthnUserEntity(user.Id, WebAuthnNameFor(user), WebAuthnNameFor(user)),
            [.. existing.Select(ToReference)],
            NormalizeLabel(request.Name),
            cancellationToken);

        return ToChallenge(start);
    }

    /// <summary>
    /// Verify the attestation and store the credential.
    /// <para>
    /// The insert and the companion identity row go in one transaction: the row that makes the
    /// capability visible on the login-methods screen must not be able to exist without a
    /// credential behind it, nor the credential without it.
    /// </para>
    /// </summary>
    public async Task<PasskeyRegistrationResponse> FinishRegistrationAsync(
        int userId,
        PasskeyRegisterFinishRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        await RequireActiveUserAsync(userId, cancellationToken);

        var registration = await ceremony.CompleteRegistrationAsync(
            request.FlowId,
            userId,
            RawCredential(request.Credential),
            cancellationToken);

        // After verification, not before: a caller who has not proved possession of the
        // authenticator must not be able to probe which credential ids are already enrolled.
        if (await passkeys.FindByCredentialIdAsync(registration.CredentialId, cancellationToken) is not null)
        {
            throw new ConflictException(
                ErrorCodes.PasskeyAlreadyRegistered,
                "That passkey is already registered.");
        }

        var now = clock.UtcNow;
        var passkey = new UserPasskey
        {
            UserId = userId,
            CredentialId = registration.CredentialId,
            PublicKey = registration.PublicKey,
            SignCount = registration.SignCount,
            Aaguid = registration.Aaguid,
            Transports = JsonSerializer.Serialize(registration.Transports),
            AttestationType = registration.AttestationFormat,
            BackupEligible = registration.BackupEligible,
            BackupState = registration.BackupState,
            Name = NormalizeLabel(request.Name) ?? registration.Label ?? UserPasskey.DefaultName,
            CreatedAt = now,
            UpdatedAt = now,
        };

        await unitOfWork.ExecuteInTransactionAsync(
            async token =>
            {
                passkeys.Add(passkey);

                // Both writes, then one save: the identity link reads the identity rows and must
                // see the state this transaction is building, and a single save keeps them atomic
                // even though they are two tables.
                await identityLink.EnsurePasskeyIdentityAsync(userId, token);
                await unitOfWork.SaveChangesAsync(token);
            },
            cancellationToken);

        logger.LogInformation(
            "Passkey {PasskeyId} registered for user {UserId} (attestation {AttestationFormat}).",
            passkey.Id,
            userId,
            registration.AttestationFormat);

        return new PasskeyRegistrationResponse
        {
            Id = passkey.Id,
            Name = passkey.Name ?? UserPasskey.DefaultName,
            CreatedAt = passkey.CreatedAt,
        };
    }

    /// <summary>
    /// Start a login.
    /// <para>
    /// An identifier only ever narrows the credential list. <b>Every way it can fail - unknown
    /// address, unsupported type, an account with no passkeys - falls through to a discoverable
    /// ceremony rather than an error</b>, so no status code, error code or message here says
    /// whether an address is registered. Refusing would turn an unauthenticated endpoint into an
    /// account-existence oracle, which is exactly what the throttle above cannot fix.
    /// </para>
    /// <para>
    /// <b>What the fall-through does not hide, and cannot:</b> a recognised identifier produces
    /// options carrying that account's credential ids in <c>allowCredentials</c>, and a miss
    /// produces an empty list. The two responses therefore differ in shape - so a caller who
    /// already knows an address can still learn that it is registered here, and learns its
    /// credential ids with it. That is inherent to identifier-scoped WebAuthn rather than a defect
    /// of this code (the list exists so the browser can pick the right key), and it is why the
    /// endpoint is throttled per IP. A deployment that will not accept the disclosure has one
    /// remedy: stop sending the identifier and use only the discoverable ceremony, which needs no
    /// change here. Credential ids are opaque handles and are useless without the private key they
    /// name, which is why the trade is worth making at all.
    /// </para>
    /// </summary>
    public async Task<PasskeyChallengeResponse> BeginLoginAsync(
        PasskeyLoginBeginRequest request,
        PasskeyRequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);

        await ChargeLoginBeginBudgetAsync(context, cancellationToken);

        var target = await ResolveLoginTargetAsync(request, cancellationToken);
        var start = await ceremony.BeginLoginAsync(target, cancellationToken);

        return ToChallenge(start);
    }

    /// <summary>
    /// Verify the assertion and record the login.
    /// <para>
    /// <b>The signature counter is checked twice on this path and that is not redundancy for its
    /// own sake.</b> The FIDO2 library checks it as part of assertion verification, and
    /// <see cref="UserPasskey.RecordAssertion"/> checks it again before it will move the stored
    /// value. The library's check could be lost by a version bump or a swapped implementation; the
    /// domain's cannot, because refusing is how the entity is written. A counter that has gone
    /// backwards is the one signal that says the private key has been extracted from the
    /// authenticator and copied, which is the entire security advantage a passkey has over a
    /// password - so it is refused loudly, with its own error code and its own log line, and never
    /// folded into the generic "verification failed".
    /// </para>
    /// </summary>
    public async Task<PasskeyLoginResponse> FinishLoginAsync(
        PasskeyLoginFinishRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var assertionRequest = await ceremony.TakeAssertionAsync(
            request.FlowId,
            RawCredential(request.Credential),
            cancellationToken);

        var passkey = await passkeys.FindByCredentialIdAsync(assertionRequest.CredentialId, cancellationToken);

        // Distinct from a failed assertion on purpose: the client needs to tell "this device is not
        // enrolled on this account, offer another sign-in method" from "that signature did not
        // check out, try again". Both are 401, so the status line reveals nothing about which
        // credential ids exist; only the error code differs.
        if (passkey is null)
        {
            throw new UnauthorizedException(
                ErrorCodes.PasskeyCredentialNotFound,
                "That passkey is not recognised.");
        }

        // An identifier-scoped ceremony pinned an account before the challenge was issued. A
        // credential that belongs to a different account cannot satisfy it, even though it would
        // verify perfectly well on its own terms.
        if (assertionRequest.UserId is { } scopedUserId && scopedUserId != passkey.UserId)
        {
            logger.LogWarning(
                "A passkey belonging to user {PasskeyOwner} was presented for a login ceremony begun "
                + "for user {FlowUser}; refusing.",
                passkey.UserId,
                scopedUserId);

            throw new UnauthorizedException(
                ErrorCodes.PasskeyCredentialNotFound,
                "That passkey is not recognised.");
        }

        var assertion = await ceremony.CompleteLoginAsync(
            assertionRequest,
            new WebAuthnStoredCredential(passkey.CredentialId, passkey.PublicKey, passkey.SignCount, passkey.UserId),
            cancellationToken);

        // Before the counter moves, not after. RecordAssertion mutates a tracked entity, so
        // refusing a disabled account afterwards would leave an advanced counter and a fresh
        // last-used stamp staged in the change tracker for a login that never happened - harmless
        // only for as long as nothing else in the request calls SaveChanges, which is not a
        // property worth depending on. (It also matters because the account-closing path in
        // AccountAppService only disables the account and its identity rows: the credential rows
        // survive, so this check is what stops a deregistered account signing in with a key it
        // still holds.)
        //
        // The cost of this order is that a disabled account presenting a cloned credential is
        // refused as a disabled account and no clone alert is raised. Accepted: that login could
        // not have succeeded either way, so the alert would describe an attack that had already
        // failed.
        var user = await RequireActiveUserAsync(passkey.UserId, cancellationToken);

        var now = clock.UtcNow;

        if (!passkey.RecordAssertion(assertion.SignCount, assertion.BackupState, now))
        {
            // Reached only if the verifier's own counter check did not fire. Logged at Error
            // because it means a credential is being answered for by two authenticators - and,
            // separately, that the layer in front of this one stopped catching it.
            logger.LogError(
                "Passkey {PasskeyId} for user {UserId} presented signature counter {Presented} "
                + "against stored {Stored}. The credential appears to have been cloned; refusing "
                + "the login and leaving the stored counter untouched.",
                passkey.Id,
                passkey.UserId,
                assertion.SignCount,
                passkey.SignCount);

            throw new UnauthorizedException(
                ErrorCodes.PasskeyPossibleClone,
                "This passkey could not be used to sign in. Remove it and enrol a new one.");
        }

        // Committed rather than best-effort. Losing this write means the counter does not advance,
        // and a counter that never advances is a clone check that silently stops working - a worse
        // outcome than telling the caller to retry a login that would otherwise have succeeded.
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return new PasskeyLoginResponse
        {
            UserId = user.Id,
            PasskeyId = passkey.Id,
            PasskeyName = passkey.Name ?? UserPasskey.DefaultName,
            AuthenticatedAt = now,
        };
    }

    /// <summary>Everything the account has enrolled. Never 404s - an account with no passkeys has
    /// an empty list, which is what the screen wants to render.</summary>
    public async Task<PasskeyListResponse> ListAsync(int userId, CancellationToken cancellationToken)
    {
        var owned = await passkeys.ListByUserAsync(userId, cancellationToken);

        return new PasskeyListResponse { Passkeys = [.. owned.Select(ToResponse)] };
    }

    /// <summary>Relabel one credential.</summary>
    public async Task<PasskeyResponse> RenameAsync(
        int userId,
        int passkeyId,
        RenamePasskeyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var passkey = await RequireOwnedPasskeyAsync(userId, passkeyId, cancellationToken);

        passkey.Rename(request.Name, clock.UtcNow);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return ToResponse(passkey);
    }

    /// <summary>
    /// Remove one credential.
    /// <para>
    /// <b>The last way into an account is not removable.</b> A user who deletes their only passkey
    /// while holding no password and no other identity has locked themselves out permanently -
    /// there is nothing left to prove who they are with, and no support path short of identity
    /// documents. 409 rather than 403: it is a conflict with the current state, and the fix is
    /// available to the caller - add a password or bind an address, then come back.
    /// </para>
    /// </summary>
    public async Task DeleteAsync(int userId, int passkeyId, CancellationToken cancellationToken)
    {
        var passkey = await RequireOwnedPasskeyAsync(userId, passkeyId, cancellationToken);

        var remaining = await passkeys.CountByUserAsync(userId, cancellationToken);
        var isLastPasskey = remaining <= 1;

        if (isLastPasskey && !await identityLink.HasNonPasskeyLoginMethodAsync(userId, cancellationToken))
        {
            throw new ConflictException(
                ErrorCodes.PasskeyLastLoginMethod,
                "This is the only way to sign in to this account. Add a password or another "
                + "sign-in method before removing it.");
        }

        await unitOfWork.ExecuteInTransactionAsync(
            async token =>
            {
                passkeys.Remove(passkey);

                if (isLastPasskey)
                {
                    // The companion row claims the account can sign in with a passkey. With the
                    // last credential gone that claim is false, and leaving it would put a
                    // sign-in option on the login screen that can never succeed.
                    await identityLink.RetirePasskeyIdentityAsync(userId, token);
                }

                await unitOfWork.SaveChangesAsync(token);
            },
            cancellationToken);
    }

    /// <summary>
    /// Spend one token from the per-minute budget and, only if it allowed the request, one from the
    /// per-hour budget. Stopping at the first refusal is what the port requires of a caller holding
    /// several policies: every call counts, so charging the hour window after the minute window has
    /// already said no bills a caller for a request nobody answered.
    /// </summary>
    private async Task ChargeLoginBeginBudgetAsync(
        PasskeyRequestContext context,
        CancellationToken cancellationToken)
    {
        var client = string.IsNullOrWhiteSpace(context.ClientIp) ? UnknownClient : context.ClientIp;

        var perMinute = await rateLimiter.TryAcquireAsync(
            LoginBeginRateLimitDimension,
            client,
            RateLimitPolicy.PerMinute(LoginBeginPerMinute),
            cancellationToken);

        if (!perMinute.Allowed)
        {
            throw RefuseLoginBegin(client, perMinute.RetryAfter);
        }

        var perHour = await rateLimiter.TryAcquireAsync(
            LoginBeginRateLimitDimension,
            client,
            RateLimitPolicy.PerHour(LoginBeginPerHour),
            cancellationToken);

        if (!perHour.Allowed)
        {
            throw RefuseLoginBegin(client, perHour.RetryAfter);
        }
    }

    private RateLimitedException RefuseLoginBegin(string client, TimeSpan retryAfter)
    {
        logger.LogWarning(
            "Passkey login-begin refused for client {ClientIp}: the per-IP budget is spent, retry in {RetryAfter}.",
            client,
            retryAfter);

        return new RateLimitedException(
            ErrorCodes.RateLimitExceeded,
            "Too many sign-in attempts from this address. Try again later.",
            retryAfter);
    }

    /// <summary>
    /// Turns an optional identifier into a set of allowed credentials. Every miss returns the
    /// discoverable target; see the remarks on <see cref="BeginLoginAsync"/> for why none of them
    /// is an error.
    /// </summary>
    private async Task<WebAuthnLoginTarget> ResolveLoginTargetAsync(
        PasskeyLoginBeginRequest request,
        CancellationToken cancellationToken)
    {
        var discoverable = new WebAuthnLoginTarget(null, []);

        if (string.IsNullOrWhiteSpace(request.Identifier)
            || string.IsNullOrWhiteSpace(request.IdentityType)
            || !IdentifierNormalizer.IsSupportedIdentityType(request.IdentityType))
        {
            return discoverable;
        }

        var identityType = IdentifierNormalizer.ResolveIdentityType(request.IdentityType);
        var identifier = IdentifierNormalizer.Normalize(identityType, request.Identifier);
        var identity = await identities.FindActiveAsync(identityType, protector.Hash(identifier), cancellationToken);

        if (identity is null)
        {
            return discoverable;
        }

        var owned = await passkeys.ListByUserAsync(identity.UserId, cancellationToken);

        return owned.Count == 0
            ? discoverable
            : new WebAuthnLoginTarget(identity.UserId, [.. owned.Select(ToReference)]);
    }

    private async Task<User> RequireActiveUserAsync(int userId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId, cancellationToken)
                   ?? throw new NotFoundException(ErrorCodes.UserNotFound, "User was not found.");

        if (!user.IsActive())
        {
            throw new ForbiddenException(ErrorCodes.AccountDisabled, "The account is not active.");
        }

        return user;
    }

    /// <summary>
    /// Loads a credential and insists it belongs to the caller.
    /// <para>
    /// Somebody else's credential id answers 404, identically to an id that was never issued. A 403
    /// would be the honest status for "exists, not yours", and it would also let anyone walk the id
    /// space and count how many passkeys the service holds.
    /// </para>
    /// </summary>
    private async Task<UserPasskey> RequireOwnedPasskeyAsync(
        int userId,
        int passkeyId,
        CancellationToken cancellationToken)
    {
        var passkey = await passkeys.FindByIdAsync(passkeyId, cancellationToken);

        if (passkey is null || passkey.UserId != userId)
        {
            throw new NotFoundException(ErrorCodes.PasskeyNotFound, "Passkey was not found.");
        }

        return passkey;
    }

    private static PasskeyChallengeResponse ToChallenge(WebAuthnCeremonyStart start) => new()
    {
        FlowId = start.FlowId,

        // The adapter produced this string from the FIDO2 library's own serializer, so a parse
        // failure here is not a client problem - it is this service having produced malformed
        // options, which is a bug and should surface as a 500 rather than an empty object.
        PublicKey = JsonNode.Parse(start.OptionsJson)
                    ?? throw new InvalidOperationException(
                        "The WebAuthn ceremony produced options that are not a JSON object."),
    };

    private static PasskeyResponse ToResponse(UserPasskey passkey) => new()
    {
        Id = passkey.Id,
        Name = passkey.Name ?? UserPasskey.DefaultName,
        LastUsedAt = passkey.LastUsedAt,
        CreatedAt = passkey.CreatedAt,
    };

    private WebAuthnCredentialReference ToReference(UserPasskey passkey) =>
        new(passkey.CredentialId, ReadTransports(passkey));

    /// <summary>
    /// Reads the stored transports array. A malformed value degrades to "no transports known"
    /// rather than failing the ceremony: transports are a hint that helps the browser pick the
    /// right prompt, and no hint is a slightly worse prompt, while an exception here would make a
    /// user with one bad row unable to sign in at all.
    /// <para>
    /// It is logged, though. The column is written from this service's own serializer, so a value
    /// that will not parse means either another writer or a format change - and a degradation
    /// nobody can see is one nobody will fix.
    /// </para>
    /// </summary>
    private IReadOnlyList<string> ReadTransports(UserPasskey passkey)
    {
        if (string.IsNullOrWhiteSpace(passkey.Transports))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<string[]>(passkey.Transports) ?? [];
        }
        catch (JsonException ex)
        {
            logger.LogWarning(
                ex,
                "Passkey {PasskeyId} has a transports value that is not a JSON array of strings; "
                + "continuing without the transport hint.",
                passkey.Id);

            return [];
        }
    }

    /// <summary>The name the authenticator shows in its credential picker. Falls back to the
    /// account id, because a blank entry in a picker full of other sites is unusable.</summary>
    private static string WebAuthnNameFor(User user) => string.IsNullOrWhiteSpace(user.Nickname)
        ? "user-" + user.Id.ToString(CultureInfo.InvariantCulture)
        : user.Nickname;

    private static string? NormalizeLabel(string? label) =>
        string.IsNullOrWhiteSpace(label) ? null : label.Trim();

    /// <summary>
    /// The credential document as the client sent it. Validation has already refused anything that
    /// is not a JSON object, so this only reaches the verifier as text - the shape is the FIDO2
    /// library's business.
    /// </summary>
    private static string RawCredential(JsonElement credential) => credential.ValueKind == JsonValueKind.Object
        ? credential.GetRawText()
        : throw new BadRequestException(
            ErrorCodes.PasskeyInvalidRequest,
            "The passkey credential is missing or is not a JSON object.");
}
