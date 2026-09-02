using FirebaseAdmin;
using FirebaseAdmin.Auth;
using Google.Apis.Auth.OAuth2;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Application.Ports.External;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// Real Firebase ID-token verification through the Firebase Admin SDK.
/// <para>
/// <b>This is not a placeholder.</b> The SDK fetches Google's public signing certificates, checks
/// the RS256 signature against the one that signed this token, and enforces expiry, issuer and
/// audience against the configured project. All of that works from
/// <see cref="FirebaseOptions.ProjectId"/> alone - no service account, no secret - because token
/// verification is a public-key operation.
/// </para>
/// <para>
/// <b>What a service account would add is the user-record read</b>, and only that. Without
/// <see cref="FirebaseOptions.CredentialsFile"/> the enrichment step is skipped and logged once;
/// sign-in still works, still verifies fully, and the only visible difference is that an account
/// whose token carried no display name starts with the default nickname. Making the credential
/// mandatory would take a working, fully verified sign-in path offline to protect a cosmetic step -
/// the wrong way round, and the reason this refuses nothing.
/// </para>
/// <para>
/// Registered as a singleton because <see cref="FirebaseApp"/> is process-global and caches the
/// public keys; a per-request instance would re-fetch Google's certificates on every sign-in.
/// </para>
/// </summary>
public sealed class FirebaseTokenVerifier : IFirebaseTokenVerifier
{
    /// <summary>
    /// The <see cref="FirebaseApp"/> instance name. Named rather than default because
    /// <c>FirebaseApp.Create</c> throws when an app of the same name already exists, and a test
    /// host that builds the container twice in one process would otherwise fail on the second.
    /// </summary>
    private const string AppName = "usersvc";

    /// <summary>The credentials path, or empty when the section will not even validate. The
    /// constructor needs it to decide whether profile enrichment is possible, and must not
    /// throw while deciding.</summary>
    private static string SafeCredentialsFile(IOptions<FirebaseOptions> options)
    {
        try
        {
            return options.Value.CredentialsFile.Trim();
        }
        catch (OptionsValidationException)
        {
            return string.Empty;
        }
    }

    private readonly IOptions<FirebaseOptions> _optionsAccessor;

    /// <summary>The validated section. Touching this is what runs validation, which is why the
    /// constructor deliberately does not.</summary>
    private FirebaseOptions _options => _optionsAccessor.Value;
    private readonly ILogger<FirebaseTokenVerifier> _logger;
    private readonly FirebaseAuth? _auth;
    private readonly bool _canReadUserRecords;

    public FirebaseTokenVerifier(
        IOptions<FirebaseOptions> options,
        ILogger<FirebaseTokenVerifier> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        // NOT options.Value. Reading it here would throw OptionsValidationException before the
        // try below, defeating the containment that block was written for - see its comment.
        _optionsAccessor = options;
        _logger = logger;

        var credentialsFile = SafeCredentialsFile(options);
        _canReadUserRecords = credentialsFile.Length > 0 && File.Exists(credentialsFile);

        if (credentialsFile.Length > 0 && !_canReadUserRecords)
        {
            // Configured but not there. Loud, because somebody meant to mount a secret and the
            // deployment silently did not - and the symptom otherwise is only thinner profiles.
            logger.LogError(
                "Firebase:CredentialsFile points at {Path}, which does not exist. Token verification "
                + "still works; profile enrichment from the Firebase user record is disabled.",
                credentialsFile);
        }
        else if (!_canReadUserRecords)
        {
            logger.LogInformation(
                "No Firebase service account is configured. ID tokens are still verified in full "
                + "against Google's public keys; the user-record profile lookup is skipped.");
        }

        try
        {
            _auth = FirebaseAuth.GetAuth(FirebaseApp.GetInstance(AppName) ?? CreateApp(credentialsFile));
        }
        catch (Exception ex)
        {
            // Deliberately EVERY exception, and deliberately not fatal.
            //
            // This type is a singleton and a constructor dependency of SocialIdentityAppService,
            // which also serves WeChat and LINE. An exception escaping here does not just disable
            // Firebase - it makes the whole app service unresolvable, so WeChat and LINE sign-in
            // answer 500 too, for a Firebase secret they never needed. That is precisely the
            // failure mode of refusing where a capability is merely constructed rather than where
            // it is used, so the blast radius is contained here and the refusal happens in
            // VerifyIdTokenAsync, which only the Firebase endpoints reach.
            //
            // A narrower filter was not enough: a service-account file that is corrupt JSON, empty,
            // or unreadable by the pod's user throws JsonException, JsonReaderException,
            // UnauthorizedAccessException or SecurityException from deep inside the Google
            // credential loader - none of which is ArgumentException, InvalidOperationException or
            // IOException.
            _logger.LogError(ex, "The Firebase SDK could not be initialised; Firebase sign-in is unavailable.");
            _auth = null;
        }
    }

    public async Task<FirebaseIdentity> VerifyIdTokenAsync(string idToken, CancellationToken cancellationToken)
    {
        var auth = _auth ?? throw new AppException(
            ErrorCodes.FirebaseConfigUnavailable,
            "Firebase sign-in is not available on this deployment.",
            500);

        // Before the SDK, so a mangled token is diagnosed as mangled rather than as a bad
        // signature. Also returns the payload, which is read again below - after verification.
        var payload = FirebaseTokenClaims.RequireWellFormed(idToken);

        FirebaseToken token;

        try
        {
            token = await auth.VerifyIdTokenAsync(idToken.Trim(), cancellationToken).ConfigureAwait(false);
        }
        catch (FirebaseAuthException ex)
        {
            throw Classify(ex);
        }

        // Defensive, and it does fire: the SDK checks these against the project it was created
        // with, and a process holding a stale FirebaseApp - or a configuration reloaded underneath
        // it - would otherwise accept a token minted for a different project.
        if (!string.Equals(token.Audience, _options.ProjectId, StringComparison.Ordinal)
            || !string.Equals(token.Issuer, Issuer(_options.ProjectId), StringComparison.Ordinal))
        {
            _logger.LogWarning(
                "A Firebase token named project audience {Audience}, not {ProjectId}.",
                token.Audience,
                _options.ProjectId);

            throw new UnauthorizedException(
                ErrorCodes.FirebaseProjectMismatch, "The Firebase sign-in token is for a different project.");
        }

        var identity = FirebaseTokenClaims.Read(payload, token.Uid);

        return _canReadUserRecords
            ? FirebaseTokenClaims.ApplyUserRecord(identity, await ReadUserProfileAsync(auth, token.Uid, cancellationToken))
            : identity;
    }

    /// <summary>
    /// Reads the Firebase user record to fill in whatever the token left blank.
    /// <para>
    /// A failure here is 502 rather than 500: we asked Google and Google did not answer, so it is
    /// an upstream fault and belongs on an upstream dashboard. A missing user record is the one
    /// exception - a token for a uid that no longer exists is a token that should not be honoured,
    /// so that one is 401.
    /// </para>
    /// </summary>
    private async Task<FirebaseUserProfile> ReadUserProfileAsync(
        FirebaseAuth auth,
        string uid,
        CancellationToken cancellationToken)
    {
        try
        {
            var record = await auth.GetUserAsync(uid, cancellationToken).ConfigureAwait(false);

            return new FirebaseUserProfile(
                record.Email ?? string.Empty,
                record.DisplayName ?? string.Empty,
                record.PhotoUrl ?? string.Empty,
                [.. (record.ProviderData ?? []).Select(p => new FirebaseProviderProfile(
                    p.ProviderId ?? string.Empty,
                    p.Email ?? string.Empty,
                    p.DisplayName ?? string.Empty,
                    p.PhotoUrl ?? string.Empty))]);
        }
        catch (FirebaseAuthException ex) when (ex.AuthErrorCode == AuthErrorCode.UserNotFound)
        {
            throw new UnauthorizedException(
                ErrorCodes.FirebaseIdTokenInvalid, "The Firebase sign-in token is not valid.", ex);
        }
        catch (FirebaseAuthException ex)
        {
            _logger.LogError(ex, "The Firebase user record for a verified token could not be read.");

            throw new UpstreamException(
                ErrorCodes.FirebaseUserLookupFailed, "Firebase could not be reached. Try again in a moment.", ex);
        }
    }

    /// <summary>
    /// Splits the SDK's rejections into the two a client can act on differently: an expired token
    /// is worth refreshing and retrying, an invalid one is not.
    /// </summary>
    private UnauthorizedException Classify(FirebaseAuthException exception)
    {
        if (exception.AuthErrorCode == AuthErrorCode.ExpiredIdToken)
        {
            return new UnauthorizedException(
                ErrorCodes.FirebaseIdTokenExpired,
                "The Firebase sign-in token has expired. Get a fresh one and try again.",
                exception);
        }

        _logger.LogWarning(exception, "A Firebase ID token failed verification.");

        return new UnauthorizedException(
            ErrorCodes.FirebaseIdTokenInvalid, "The Firebase sign-in token is not valid.", exception);
    }

    /// <summary>
    /// Builds the app. A credential is required by <see cref="AppOptions"/> even though token
    /// verification never uses one, so an unconfigured deployment gets a placeholder access token
    /// that is never sent anywhere - <see cref="_canReadUserRecords"/> is false in that case and
    /// the only call that would authenticate with it is skipped.
    /// </summary>
    private FirebaseApp CreateApp(string credentialsFile) => FirebaseApp.Create(
        new AppOptions
        {
            // CredentialFactory.FromFile<ServiceAccountCredential> rather than
            // GoogleCredential.FromFile, which Google deprecated: the untyped overload will build
            // whatever credential kind the file happens to describe, so a file swapped for a
            // user-credential or external-account JSON would be honoured silently. Naming the type
            // makes anything other than a service account fail at startup, where it is cheap.
            Credential = _canReadUserRecords
                ? CredentialFactory.FromFile<ServiceAccountCredential>(credentialsFile).ToGoogleCredential()
                : GoogleCredential.FromAccessToken(UnconfiguredAccessToken),
            ProjectId = _options.ProjectId,
        },
        AppName);

    private static string Issuer(string projectId) => "https://securetoken.google.com/" + projectId;

    /// <summary>
    /// Stand-in credential for a deployment with no service account. The SDK insists on one to
    /// build a <see cref="FirebaseApp"/>, but token verification is a public-key operation and
    /// never presents it - and the one call that would, the user-record read, is gated on
    /// <see cref="_canReadUserRecords"/>. It is a constant so that a value showing up in a Google
    /// 401 is unmistakably this and not a real token that leaked.
    /// </summary>
    private const string UnconfiguredAccessToken = "firebase-user-record-lookup-not-configured";
}
