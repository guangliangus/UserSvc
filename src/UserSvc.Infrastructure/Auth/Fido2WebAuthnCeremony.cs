using System.Buffers.Binary;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Auth;
using UserSvc.Infrastructure.Platform;

namespace UserSvc.Infrastructure.Auth;

/// <summary>
/// Relying-party settings for WebAuthn.
/// <para>
/// <b>All three of these are load-bearing and none of them has a safe default.</b>
/// <see cref="RpId"/> is baked into every credential an authenticator creates: change it and every
/// passkey in the user base stops working, permanently, because the authenticator will not offer a
/// credential whose RP id does not match. <see cref="Origins"/> is the list of app and web origins
/// allowed to complete a ceremony - it is the whole of the phishing resistance, so a wildcard or a
/// wrong entry gives it away. Both must match the domain that serves the platform association files
/// (<c>apple-app-site-association</c>, <c>assetlinks.json</c>). There is deliberately no default
/// value for either: a service booting with somebody else's RP id would look like it worked.
/// </para>
/// </summary>
public sealed class PasskeyOptions : IValidatableObject
{
    public const string SectionName = "Passkey";

    /// <summary>The relying-party id: the registrable domain, with no scheme and no port -
    /// <c>liontrip.com</c>, not <c>https://liontrip.com/</c>.</summary>
    [Required]
    public string RpId { get; init; } = string.Empty;

    /// <summary>The name the authenticator shows the user when it asks them to confirm.</summary>
    [Required]
    public string RpDisplayName { get; init; } = string.Empty;

    /// <summary>
    /// Every origin allowed to complete a ceremony: <c>https://liontrip.com</c> for the web, and
    /// one <c>android:apk-key-hash:…</c> entry per Android signing certificate.
    /// </summary>
    [Required]
    [MinLength(1)]
    public string[] Origins { get; init; } = [];

    /// <summary>
    /// How long a begun ceremony may sit unfinished.
    /// <para>
    /// It bounds the window in which a challenge is replayable, and it is also the user's window to
    /// pick a key and touch a sensor. Five minutes is the Go service's value and is generous for
    /// the second purpose; anything much longer only helps the first.
    /// </para>
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:30", "00:30:00")]
    public TimeSpan ChallengeTtl { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The origins actually accepted at verification time.
    /// <para>
    /// <b>Every configured <c>android:apk-key-hash:</c> origin is expanded into its base64 spelling
    /// variants, and that is a workaround for a real bug in the field, not laxity.</b> The WebAuthn
    /// canonical form of an APK signing-certificate hash is unpadded base64url, and Google Play
    /// Services emits exactly that - but the credential providers shipped by several Android OEMs
    /// (Xiaomi's HyperOS among them, and some OPPO, vivo and Huawei builds) emit standard base64
    /// instead, with <c>+</c>, <c>/</c> and <c>=</c> padding. The verifier compares origins as
    /// whole strings, so those users would be refused at the last step of every ceremony with a
    /// message about origins that names an origin that looks identical to the configured one.
    /// </para>
    /// <para>
    /// The Go service solved this by rewriting the incoming origin before comparing. That is not
    /// available here - the origin lives inside the signed <c>clientDataJSON</c>, and rewriting
    /// those bytes would invalidate the signature they are covered by - so the equivalent
    /// acceptance set is built on the configuration side instead, which touches nothing signed.
    /// Only apk-key-hash origins are expanded; a web origin is passed through untouched.
    /// </para>
    /// </summary>
    public IReadOnlySet<string> BuildOriginSet()
    {
        var origins = new HashSet<string>(StringComparer.Ordinal);

        foreach (var configured in Origins)
        {
            var origin = configured.Trim();
            if (origin.Length == 0)
            {
                continue;
            }

            origins.Add(origin);

            if (!origin.StartsWith(ApkKeyHashPrefix, StringComparison.Ordinal))
            {
                continue;
            }

            var hash = origin[ApkKeyHashPrefix.Length..].TrimEnd('=');
            var urlSafe = hash.Replace('+', '-').Replace('/', '_');
            var standard = hash.Replace('-', '+').Replace('_', '/');
            var padding = new string('=', (4 - (hash.Length % 4)) % 4);

            origins.Add(ApkKeyHashPrefix + urlSafe);
            origins.Add(ApkKeyHashPrefix + urlSafe + padding);
            origins.Add(ApkKeyHashPrefix + standard);
            origins.Add(ApkKeyHashPrefix + standard + padding);
        }

        return origins;
    }

    /// <summary>The scheme every Android origin carries. Its payload is the SHA-256 of the app's
    /// signing certificate.</summary>
    private const string ApkKeyHashPrefix = "android:apk-key-hash:";

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (RpId.Contains("://", StringComparison.Ordinal) || RpId.EndsWith('/'))
        {
            yield return new ValidationResult(
                "Passkey:RpId is a bare registrable domain - 'liontrip.com', not a URL.",
                [nameof(RpId)]);
        }

        // A blank entry is refused rather than quietly skipped. BuildOriginSet drops blanks, so a
        // configuration of [""] - which is exactly what an environment variable set to nothing
        // produces - would otherwise validate and then hand the verifier an empty accepted-origin
        // set. Every ceremony would fail at its last step, on a deployment that looks configured,
        // with a log line about an origin mismatch against nothing.
        if (Origins.Any(string.IsNullOrWhiteSpace))
        {
            yield return new ValidationResult(
                "Passkey:Origins contains a blank entry. Remove it: an origin list that ends up "
                + "empty accepts nothing, and every passkey ceremony would fail at the origin check.",
                [nameof(Origins)]);
        }

        foreach (var origin in Origins.Select(o => o.Trim()).Where(o => o.Length > 0))
        {
            // The library calls Uri on every configured origin while building its comparison set,
            // and an unparseable one throws out of the first ceremony rather than out of startup.
            if (!Uri.IsWellFormedUriString(origin, UriKind.Absolute))
            {
                yield return new ValidationResult(
                    $"Passkey:Origins contains '{origin}', which is not an absolute URI. Web origins "
                    + "look like 'https://liontrip.com'; Android origins like "
                    + "'android:apk-key-hash:<base64url sha-256 of the signing certificate>'.",
                    [nameof(Origins)]);
            }
        }
    }
}

/// <summary>
/// The state that spans a ceremony's two requests.
/// </summary>
/// <param name="Mode">
/// <c>register</c>, <c>login_identifier</c> or <c>login_discoverable</c>. It is checked at finish
/// time, so a registration challenge cannot be spent as a login and vice versa.
/// </param>
/// <param name="UserId">Who began it: the registering account, the account an identifier-scoped
/// login was narrowed to, or null for a discoverable login.</param>
/// <param name="Label">The credential label the client suggested at begin time.</param>
/// <param name="OptionsJson">The serialized options - challenge, allowed or excluded credentials,
/// user verification - exactly as they were sent to the browser.</param>
public sealed record PasskeyFlow(
    [property: JsonPropertyName("mode")] string Mode,
    [property: JsonPropertyName("userId")] int? UserId,
    [property: JsonPropertyName("label")] string? Label,
    [property: JsonPropertyName("options")] string OptionsJson);

/// <summary>
/// Where a half-finished ceremony waits. Split out from the ceremony itself so that the
/// cryptography can be exercised in a unit test without a Redis.
/// </summary>
public interface IPasskeyFlowStore
{
    Task StoreAsync(string flowId, PasskeyFlow flow, TimeSpan ttl, CancellationToken cancellationToken);

    /// <summary>
    /// Reads the flow and deletes it in the same operation. <b>Single use is the point</b>: a
    /// challenge that survives its first finish attempt is a challenge an attacker can keep
    /// grinding against, and one that survives a <i>successful</i> finish is a replayable login.
    /// </summary>
    /// <returns>Null when there is no such flow - expired, already spent, or never issued.</returns>
    Task<PasskeyFlow?> TakeAsync(string flowId, CancellationToken cancellationToken);
}

/// <summary>
/// Ceremony state on Redis, under <c>{prefix}passkey:flow:{flowId}</c> with the challenge TTL.
/// <para>
/// <b>Redis rather than PostgreSQL, deliberately.</b> This row's whole life is one browser prompt:
/// it is written on begin, read once on finish and then worthless. In the database that is an
/// INSERT plus a DELETE per <i>attempted</i> login - abandoned prompts included, and login-begin is
/// an unauthenticated endpoint anyone can call - so the durable, replicated, backed-up store would
/// carry a write rate driven by strangers, plus a sweeper for the rows nobody ever comes back for.
/// Redis expires them for free and this service already runs one.
/// </para>
/// <para>
/// <b>The failure mode that buys is: Redis down means nobody can sign in with a passkey, loudly.</b>
/// Both operations fail closed, which is the opposite of how the same Redis is treated for the
/// revocation set - and the asymmetry is the same one <c>docs/architecture.md</c> already draws.
/// The revocation read fails open because a validated short-lived token is a fallback underneath
/// it; here there is no fallback underneath, because the challenge <i>is</i> the security property.
/// A begin that could not store its challenge must not hand the client one, and a finish that
/// cannot find the challenge it issued must not verify against one the client supplied. Users fall
/// back to another sign-in method for the duration; nothing is silently accepted.
/// </para>
/// </summary>
public sealed class RedisPasskeyFlowStore(
    IConnectionMultiplexer connection,
    IOptions<RedisOptions> redisOptions,
    ILogger<RedisPasskeyFlowStore> logger) : IPasskeyFlowStore
{
    /// <summary>
    /// Read at the point of use, never in a field initializer (docs/architecture.md: "a missing
    /// capability may only break itself"). A field initializer runs during construction, and
    /// <see cref="IOptions{TOptions}.Value"/> is where DataAnnotations validation runs - so
    /// binding it into a field makes merely constructing this store throw on a bad <c>Redis</c>
    /// section, which is a different capability from the one this file is about.
    /// <see cref="IOptions{TOptions}.Value"/> caches, so the property costs nothing per call.
    /// </summary>
    private string _keyPrefix => redisOptions.Value.KeyPrefix;

    public async Task StoreAsync(
        string flowId,
        PasskeyFlow flow,
        TimeSpan ttl,
        CancellationToken cancellationToken)
    {
        // No StackExchange.Redis async method takes a CancellationToken; it is honoured at the
        // boundary only, and the issued command is not cancellable.
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            await connection.GetDatabase().StringSetAsync(
                KeyFor(flowId),
                JsonSerializer.Serialize(flow),
                expiry: ttl,
                keepTtl: false,
                when: When.Always,
                flags: CommandFlags.None);
        }
        catch (Exception ex) when (IsRedisFault(ex))
        {
            throw Unavailable("store", ex);
        }
    }

    public async Task<PasskeyFlow?> TakeAsync(string flowId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        RedisValue stored;

        try
        {
            // GETDEL: read and delete in one round trip, so two concurrent finishes cannot both
            // see the challenge. A GET followed by a DEL would leave exactly that gap.
            stored = await connection.GetDatabase().StringGetDeleteAsync(KeyFor(flowId), CommandFlags.None);
        }
        catch (Exception ex) when (IsRedisFault(ex))
        {
            throw Unavailable("read", ex);
        }

        if (stored.IsNullOrEmpty)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<PasskeyFlow>(stored.ToString());
        }
        catch (JsonException ex)
        {
            // Treated as a miss, and the caller answers "start again". Error rather than warning
            // because a value we wrote ourselves failing to parse means either a format change
            // that skipped a deployment step or something else writing into our key space.
            logger.LogError(ex, "The stored passkey ceremony {FlowId} could not be read back.", flowId);
            return null;
        }
    }

    private string KeyFor(string flowId) => $"{_keyPrefix}passkey:flow:{flowId}";

    /// <summary>
    /// The StackExchange.Redis hierarchy is not what it looks like: <c>RedisTimeoutException</c>
    /// derives from <see cref="TimeoutException"/> and <c>RedisCommandException</c> straight from
    /// <see cref="Exception"/>, so catching <c>RedisException</c> alone misses every timeout.
    /// </summary>
    private static bool IsRedisFault(Exception ex) =>
        ex is RedisException or RedisTimeoutException or RedisCommandException;

    private UpstreamException Unavailable(string operation, Exception cause)
    {
        logger.LogError(
            cause,
            "Could not {Operation} a passkey ceremony on Redis; passkey sign-in is unavailable until "
            + "it recovers.",
            operation);

        return new UpstreamException(
            ErrorCodes.UpstreamUnavailable,
            "Passkey sign-in is temporarily unavailable. Try again shortly.",
            cause);
    }
}

/// <summary>
/// The WebAuthn verifier, on fido2-net-lib.
/// <para>
/// This class holds every piece of knowledge about the FIDO2 library that exists in the service:
/// the options it builds, the exceptions it throws, and the shape of the credential JSON a browser
/// produces. Everything above it sees the plain records of <see cref="IWebAuthnCeremony"/>.
/// </para>
/// <para>
/// <b>The one place it does more than delegate is the signature-counter failure.</b> The library
/// reports a regressed counter as one more <see cref="Fido2VerificationException"/> among two dozen
/// others, and answering all of them alike would bury the single most important thing this service
/// can learn about a credential - that it has been cloned - underneath "verification failed", where
/// no alert would ever find it. So <see cref="Fido2ErrorCode.InvalidSignCount"/> is picked out by
/// hand and given its own error code and its own log line.
/// </para>
/// <para>
/// <b>The <c>Fido2</c> instance is immutable and built once, but it is built on the first ceremony
/// rather than in the constructor, and that difference is the whole of a measured outage.</b>
/// <c>Passkey</c> is the one section in this service registered without
/// <c>ValidateOnStart()</c> - deliberately, because a relying-party identity is not something every
/// deployment has yet - so <see cref="IOptions{TOptions}.Value"/> is where its validation actually
/// runs. Reading it in the constructor therefore threw while the <i>controller</i> was being
/// activated, before any action method or its consumer-plane guard ran, and no deployment carries a
/// <c>Passkey</c> section today. Measured on this host: <c>GET /api/v1/auth/passkey</c>, its
/// <c>PATCH</c> and its <c>DELETE</c> - three pure database operations that never touch a
/// relying-party identity - all answered 500 <c>NOT_CONFIGURED</c> naming <c>RpId</c>, so an
/// account that enrolled a credential while the section was present could not list or remove it
/// afterwards; and a back-office token on any of those routes got that same 500 where every other
/// consumer endpoint answers 403 <c>FORBIDDEN</c>, because the throw beat
/// <c>ICurrentUser.RequireConsumerId()</c> to it. Both are the failure
/// <c>docs/architecture.md</c> records as "a missing capability may only break itself".
/// </para>
/// <para>
/// The deferral changes nothing else, on purpose: the instance is still one per process, still
/// immutable, and a missing section still surfaces as 500 <c>NOT_CONFIGURED</c> naming the section,
/// because <see cref="Lazy{T}"/> rethrows the factory's own <c>OptionsValidationException</c>
/// rather than wrapping it.
/// </para>
/// </summary>
public sealed class Fido2WebAuthnCeremony : IWebAuthnCeremony
{
    private const string RegisterMode = "register";
    private const string IdentifierLoginMode = "login_identifier";
    private const string DiscoverableLoginMode = "login_discoverable";

    private const string RegisterFlowPrefix = "pkreg_";
    private const string LoginFlowPrefix = "pklogin_";

    /// <summary>Refused with the same words whatever went wrong with the flow, so that a caller
    /// cannot tell "never existed" from "already spent" from "meant for someone else".</summary>
    private const string FlowExpiredMessage = "This passkey request has expired. Start again.";

    private readonly IPasskeyFlowStore _flows;
    private readonly IOptions<PasskeyOptions> _options;
    private readonly ILogger<Fido2WebAuthnCeremony> _logger;
    private readonly Lazy<IFido2> _lazyFido2;

    public Fido2WebAuthnCeremony(
        IPasskeyFlowStore flows,
        IOptions<PasskeyOptions> options,
        ILogger<Fido2WebAuthnCeremony> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _flows = flows;
        _options = options;
        _logger = logger;

        // ExecutionAndPublication: one Fido2 for the process even if several ceremonies begin at
        // once. The factory is what reads the section, so it is read on the first ceremony rather
        // than while this singleton is being constructed - see the class remarks.
        _lazyFido2 = new Lazy<IFido2>(
            () =>
            {
                var passkey = options.Value;

                return new Fido2(new Fido2Configuration
                {
                    ServerDomain = passkey.RpId,
                    ServerName = passkey.RpDisplayName,
                    Origins = passkey.BuildOriginSet(),
                });
            },
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <summary>
    /// The verifier, built exactly once from the validated section on the first ceremony that needs
    /// it. Every call site reads this property, so the deferral is invisible above it.
    /// </summary>
    private IFido2 _fido2 => _lazyFido2.Value;

    /// <summary>
    /// Read at the point of use, and deliberately not folded into the <see cref="Lazy{T}"/> above.
    /// That <see cref="Lazy{T}"/> exists to build one immutable verifier; a duration is not part of
    /// a verifier, and capturing it there would mean the section is read for a reason that has
    /// nothing to do with the object being built. <see cref="IOptions{TOptions}.Value"/> caches, so
    /// two point-of-use reads cost no more than one.
    /// </summary>
    private TimeSpan _challengeTtl => _options.Value.ChallengeTtl;

    public async Task<WebAuthnCeremonyStart> BeginRegistrationAsync(
        WebAuthnUserEntity user,
        IReadOnlyList<WebAuthnCredentialReference> excludeCredentials,
        string? label,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(excludeCredentials);

        var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User
            {
                Id = UserHandle(user.UserId),
                Name = user.Name,
                DisplayName = user.DisplayName,
            },

            // Everything the account already holds. An authenticator that recognises one of its own
            // credentials in this list refuses the ceremony, which is how a user who taps "add a
            // passkey" twice on one phone gets told rather than silently accumulating duplicates.
            ExcludeCredentials = [.. excludeCredentials.Select(ToDescriptor)],

            AuthenticatorSelection = new AuthenticatorSelection
            {
                // A passkey is by definition a discoverable credential: the authenticator has to be
                // able to offer it before anyone has typed a username, which is the entire
                // user-facing point. Anything weaker produces a credential that can only be used in
                // an identifier-first flow.
                ResidentKey = ResidentKeyRequirement.Required,

                // Preferred, not Required. Required refuses an authenticator with no biometric or
                // PIN at all, and the ones that have them verify anyway; the practical effect of
                // Required is to lock out a minority of hardware keys rather than to raise the bar.
                UserVerification = UserVerificationRequirement.Preferred,
            },

            // We do not check attestation against a metadata service, so asking for a statement
            // would collect a device identifier we have no use for and, on some platforms, show the
            // user an extra consent prompt for the privilege.
            AttestationPreference = AttestationConveyancePreference.None,
        });

        var flowId = NewFlowId(RegisterFlowPrefix);
        await StoreAsync(flowId, new PasskeyFlow(RegisterMode, user.UserId, label, options.ToJson()), cancellationToken);

        return new WebAuthnCeremonyStart(flowId, options.ToJson());
    }

    public async Task<WebAuthnRegistration> CompleteRegistrationAsync(
        string flowId,
        int userId,
        string credentialJson,
        CancellationToken cancellationToken)
    {
        var flow = await TakeFlowAsync(flowId, cancellationToken);

        if (flow.Mode != RegisterMode || flow.UserId != userId)
        {
            // Not an authorization failure with its own code: telling a caller "that flow belongs
            // to someone else" would confirm the flow id is real.
            _logger.LogWarning(
                "Passkey registration flow {FlowId} was begun as {Mode} for user {FlowUser} and "
                + "finished by user {FinishUser}; refusing.",
                flowId,
                flow.Mode,
                flow.UserId,
                userId);

            throw new BadRequestException(ErrorCodes.PasskeyFlowExpired, FlowExpiredMessage);
        }

        var attestation = Parse<AuthenticatorAttestationRawResponse>(credentialJson, "credential");

        RegisteredPublicKeyCredential credential;

        try
        {
            credential = await _fido2.MakeNewCredentialAsync(
                new MakeNewCredentialParams
                {
                    AttestationResponse = attestation,
                    OriginalOptions = CredentialCreateOptions.FromJson(flow.OptionsJson),

                    // Always "unique". The application service checks the credential id against our
                    // own table straight after this call, because a duplicate deserves the distinct
                    // "you have already registered this key" answer and the library would fold it
                    // into a generic verification failure.
                    IsCredentialIdUniqueToUserCallback = (_, _) => Task.FromResult(true),
                },
                cancellationToken);
        }
        catch (Fido2VerificationException ex)
        {
            // The whole message, not a summary: the library packs the actual cause - origin
            // mismatch, wrong challenge, bad RP id hash, a rejected attestation statement - into
            // the text, and without it every failed registration looks the same in the log.
            _logger.LogWarning(
                ex,
                "Passkey registration verification failed for user {UserId} ({Fido2ErrorCode}).",
                userId,
                ex.Code);

            throw new BadRequestException(
                ErrorCodes.PasskeyVerificationFailed,
                "This passkey could not be verified. Try again.",
                ex);
        }

        return new WebAuthnRegistration(
            credential.Id,
            credential.PublicKey,
            credential.SignCount,

            // All-zero means the authenticator declined to identify its model, which most platform
            // authenticators do. Stored as NULL rather than sixteen zero bytes, so "did not say"
            // and "said nothing meaningful" are not two different values in the column.
            credential.AaGuid == Guid.Empty ? null : credential.AaGuid.ToByteArray(bigEndian: true),
            [.. (credential.Transports ?? []).Select(EnumNameMapper<AuthenticatorTransport>.GetName)],
            credential.AttestationFormat,
            credential.IsBackupEligible,
            credential.IsBackedUp,
            flow.Label);
    }

    public async Task<WebAuthnCeremonyStart> BeginLoginAsync(
        WebAuthnLoginTarget target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            // Empty means discoverable: the authenticator offers whatever it holds for this RP id,
            // and no list of this account's credential ids goes out to an unauthenticated caller.
            AllowedCredentials = [.. target.AllowCredentials.Select(ToDescriptor)],
            UserVerification = UserVerificationRequirement.Preferred,
        });

        var mode = target.UserId is null ? DiscoverableLoginMode : IdentifierLoginMode;
        var flowId = NewFlowId(LoginFlowPrefix);

        await StoreAsync(flowId, new PasskeyFlow(mode, target.UserId, null, options.ToJson()), cancellationToken);

        return new WebAuthnCeremonyStart(flowId, options.ToJson());
    }

    public async Task<WebAuthnAssertionRequest> TakeAssertionAsync(
        string flowId,
        string credentialJson,
        CancellationToken cancellationToken)
    {
        var flow = await TakeFlowAsync(flowId, cancellationToken);

        if (flow.Mode is not (IdentifierLoginMode or DiscoverableLoginMode))
        {
            _logger.LogWarning(
                "Passkey flow {FlowId} was begun as {Mode} and finished as a login; refusing.",
                flowId,
                flow.Mode);

            throw new BadRequestException(ErrorCodes.PasskeyFlowExpired, FlowExpiredMessage);
        }

        var assertion = Parse<AuthenticatorAssertionRawResponse>(credentialJson, "assertion");

        if (assertion.RawId is not { Length: > 0 })
        {
            throw new BadRequestException(
                ErrorCodes.PasskeyInvalidRequest,
                "The passkey assertion does not name a credential.");
        }

        return new WebAuthnAssertionRequest(flow.OptionsJson, flow.UserId, assertion.RawId, credentialJson);
    }

    public async Task<WebAuthnAssertion> CompleteLoginAsync(
        WebAuthnAssertionRequest request,
        WebAuthnStoredCredential credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(credential);

        var assertion = Parse<AuthenticatorAssertionRawResponse>(request.CredentialJson, "assertion");
        var expectedHandle = UserHandle(credential.UserId);

        try
        {
            var result = await _fido2.MakeAssertionAsync(
                new MakeAssertionParams
                {
                    AssertionResponse = assertion,
                    OriginalOptions = AssertionOptions.FromJson(request.CeremonyState),
                    StoredPublicKey = credential.PublicKey,
                    StoredSignatureCounter = ToCounter(credential.SignCount),

                    // Consulted only when the authenticator sent a user handle, which a
                    // discoverable credential always does. It is what stops one account's
                    // authenticator asserting another account's credential id.
                    IsUserHandleOwnerOfCredentialIdCallback = (parameters, _) =>
                        Task.FromResult(parameters.UserHandle.AsSpan().SequenceEqual(expectedHandle)),
                },
                cancellationToken);

            return new WebAuthnAssertion(result.CredentialId, result.SignCount, result.IsBackedUp);
        }
        catch (Fido2VerificationException ex) when (ex.Code == Fido2ErrorCode.InvalidSignCount)
        {
            // The one verification failure that is not "try again". A signature counter that did
            // not advance means two authenticators are answering for one credential: the private
            // key has left the device it was generated on. Error level and its own error code,
            // because this is the alert worth waking somebody for and it must never look like a
            // mistyped PIN.
            _logger.LogError(
                ex,
                "Signature counter regression on passkey for user {UserId} (stored {StoredSignCount}). "
                + "The credential appears to have been cloned.",
                credential.UserId,
                credential.SignCount);

            throw new UnauthorizedException(
                ErrorCodes.PasskeyPossibleClone,
                "This passkey could not be used to sign in. Remove it and enrol a new one.",
                ex);
        }
        catch (Fido2VerificationException ex)
        {
            _logger.LogWarning(
                ex,
                "Passkey assertion verification failed for user {UserId} ({Fido2ErrorCode}).",
                credential.UserId,
                ex.Code);

            // 401, where the same failure during registration is a 400: here the caller was trying
            // to authenticate and has not, so "re-authenticate" is the honest instruction.
            throw new UnauthorizedException(
                ErrorCodes.PasskeyVerificationFailed,
                "That passkey could not be verified.",
                ex);
        }
    }

    /// <summary>
    /// The stable per-account user handle: eight bytes, big-endian, of the account id.
    /// <para>
    /// Eight bytes rather than four because that is what the Go service wrote, and the handle is
    /// baked into every credential an authenticator has already stored - narrowing it now would
    /// orphan every passkey enrolled before the change. Big-endian for the same reason.
    /// </para>
    /// <para>
    /// It is an opaque account reference and nothing is ever located by it: logins are found by
    /// credential id. It exists so the authenticator can tell two accounts on this site apart.
    /// </para>
    /// </summary>
    private static byte[] UserHandle(int userId)
    {
        var handle = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(handle, (uint)userId);
        return handle;
    }

    /// <summary>
    /// 128 bits of randomness behind a prefix that says which ceremony it belongs to. The flow id
    /// is a bearer handle to a pending ceremony, so it is sized like one; the prefix is there so a
    /// value in a log or a bug report is recognisable.
    /// </summary>
    private static string NewFlowId(string prefix) =>
        prefix + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

    private async Task StoreAsync(string flowId, PasskeyFlow flow, CancellationToken cancellationToken) =>
        await _flows.StoreAsync(flowId, flow, _challengeTtl, cancellationToken);

    private async Task<PasskeyFlow> TakeFlowAsync(string flowId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(flowId))
        {
            throw new BadRequestException(ErrorCodes.PasskeyFlowExpired, FlowExpiredMessage);
        }

        return await _flows.TakeAsync(flowId, cancellationToken)
               ?? throw new BadRequestException(ErrorCodes.PasskeyFlowExpired, FlowExpiredMessage);
    }

    private static PublicKeyCredentialDescriptor ToDescriptor(WebAuthnCredentialReference reference) =>
        new(
            PublicKeyCredentialType.PublicKey,
            reference.CredentialId,
            [.. reference.Transports
                .Select(t => EnumNameMapper<AuthenticatorTransport>.TryGetValue(t, out var transport)
                    ? transport
                    : (AuthenticatorTransport?)null)
                .Where(t => t is not null)
                .Select(t => t!.Value)]);

    /// <summary>
    /// WebAuthn's counter is 32 bits and ours is a <c>bigint</c>. Saturating rather than wrapping:
    /// a stored value beyond the 32-bit range can only come from corruption, and wrapping it would
    /// hand back a small number that every future assertion would beat - which is exactly the
    /// comparison the clone check depends on.
    /// </summary>
    private static uint ToCounter(long signCount) =>
        signCount <= 0 ? 0 : signCount >= uint.MaxValue ? uint.MaxValue : (uint)signCount;

    /// <summary>
    /// Reads a browser-produced credential document. A parse failure is the client's problem and is
    /// reported as one; the exception text is not returned, because it quotes the input.
    /// </summary>
    private static T Parse<T>(string json, string what)
        where T : class
    {
        try
        {
            return JsonSerializer.Deserialize<T>(json)
                   ?? throw new BadRequestException(
                       ErrorCodes.PasskeyInvalidRequest,
                       string.Create(CultureInfo.InvariantCulture, $"The passkey {what} is not valid."));
        }
        catch (JsonException ex)
        {
            throw new BadRequestException(
                ErrorCodes.PasskeyInvalidRequest,
                string.Create(CultureInfo.InvariantCulture, $"The passkey {what} is not valid."),
                ex);
        }
    }
}
