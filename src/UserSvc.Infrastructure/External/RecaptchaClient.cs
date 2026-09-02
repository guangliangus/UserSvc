using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Polly;
using UserSvc.Application.Errors;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// One assessment of one provider token. It is <b>not</b> a port: nothing in the application layer
/// substitutes it, and the only reason it is an interface at all is that
/// <see cref="RiskControlService"/> must be unit-testable without a Google account. Ports carry the
/// hexagon's boundary; this is a seam inside one adapter.
/// </summary>
public interface ICaptchaVerifier
{
    /// <summary>
    /// Whether a provider secret is present for this deployment.
    /// <para>
    /// The risk engine reads it before it decides to demand a CAPTCHA. Sending a user to solve a
    /// challenge that nothing can assess is worse than not challenging at all - the user cannot
    /// win, and every send-code request past the threshold becomes permanently unanswerable.
    /// </para>
    /// </summary>
    bool IsConfigured { get; }

    /// <summary>
    /// Asks the provider whether this token is genuine and good enough.
    /// <para>
    /// Returns a decision for anything the provider is entitled to say - a low score, a wrong
    /// action, a token already spent. Throws only when nobody could answer the question: no secret
    /// configured (500), the provider unreachable or erroring (502), the provider rejecting
    /// <i>our</i> credentials (500). <b>A failure to reach a verdict is never a pass.</b>
    /// </para>
    /// </summary>
    Task<CaptchaAssessment> AssessAsync(CaptchaAssessmentRequest request, CancellationToken cancellationToken);
}

/// <summary>What the provider is asked about.</summary>
/// <param name="ProviderToken">The token the client's SDK produced.</param>
/// <param name="Platform">Selects the platform's secret; falls back to the default one.</param>
/// <param name="ClientIpAddress">Peer address, sent as <c>remoteip</c>. Null when unknown.</param>
/// <param name="UserAgent">Caller's user agent. siteverify has no field for it; it is carried for
/// the log line that explains a refusal.</param>
public sealed record CaptchaAssessmentRequest(
    string ProviderToken,
    string Platform,
    string? ClientIpAddress,
    string? UserAgent);

/// <summary>
/// The provider's verdict.
/// </summary>
/// <param name="Passed">Whether the token cleared every check.</param>
/// <param name="Reason">
/// Why it did not, for the log only. <b>It must never reach the response body</b>: "score 0.1"
/// tells an attacker exactly how far their automation is from the threshold, which is a free
/// oracle for tuning it.
/// </param>
/// <param name="Score">The v3 risk score, or null for a key that does not produce one (a v2
/// checkbox key). Null means the score threshold does not apply, not that the score was zero.</param>
public sealed record CaptchaAssessment(bool Passed, string Reason, double? Score)
{
    public static CaptchaAssessment Pass(double? score) => new(true, "passed", score);

    public static CaptchaAssessment Fail(string reason, double? score = null) => new(false, reason, score);
}

/// <summary>
/// Where reCAPTCHA lives, which secret talks to it, and how hard a token has to try.
/// <para>
/// <b>None of the secrets is <see cref="RequiredAttribute"/>, and that is a decision rather than an
/// oversight.</b> Marking them required would make a deployment with no Google account refuse to
/// boot - and reCAPTCHA is needed by exactly one endpoint out of the whole service. Login,
/// registration, sessions, the entire back office and even the send-code throttle itself work
/// without it. Trading all of that for a boot-time reminder puts the failure on a path everything
/// crosses, to protect a path almost nothing does.
/// </para>
/// <para>
/// So the failure is typed and local instead: <see cref="RecaptchaClient.IsConfigured"/> is false,
/// the risk engine stops demanding CAPTCHAs it cannot mint tokens for, and
/// <c>POST /verification/captcha/verify</c> answers 500 with a log line naming this section. What
/// <i>is</i> validated is the shape of everything that is present - a secret that is set but points
/// at a malformed endpoint, or a threshold outside [0,1], still refuses to boot, because those are
/// mistakes rather than absences.
/// </para>
/// </summary>
public sealed class RecaptchaOptions : IValidatableObject
{
    public const string SectionName = "Recaptcha";

    /// <summary>
    /// Absolute base address, trailing slash included. The default is Google's public verifier;
    /// override it for the regional mirror (<c>https://www.recaptcha.net/recaptcha/</c>) or for a
    /// test double.
    /// </summary>
    [Required]
    public string BaseAddress { get; init; } = "https://www.google.com/recaptcha/";

    /// <summary>Path of the siteverify endpoint, relative to <see cref="BaseAddress"/> and without
    /// a leading slash - a rooted value silently discards the base path.</summary>
    [Required]
    public string VerifyPath { get; init; } = "api/siteverify";

    /// <summary>
    /// The shared secret paired with the site key. <b>A server secret: never log it, never return
    /// it.</b> Empty means this deployment has no CAPTCHA provider.
    /// </summary>
    public string Secret { get; init; } = string.Empty;

    /// <summary>Secret for the web site key, when the deployment issues one key per platform.
    /// Falls back to <see cref="Secret"/>.</summary>
    public string SecretWeb { get; init; } = string.Empty;

    /// <summary>Secret for the Android site key. Falls back to <see cref="Secret"/>.</summary>
    public string SecretAndroid { get; init; } = string.Empty;

    /// <summary>Secret for the iOS site key. Falls back to <see cref="Secret"/>.</summary>
    public string SecretIos { get; init; } = string.Empty;

    /// <summary>
    /// Lowest v3 score that passes. 0 switches the score check off, which is what a v2 checkbox key
    /// needs - those return no score at all, and a threshold above zero would refuse every one of
    /// their tokens.
    /// </summary>
    [Range(0.0, 1.0)]
    public double MinScore { get; init; } = 0.5;

    /// <summary>
    /// The action name the client's SDK was told to use. Empty switches the check off.
    /// <para>
    /// Worth setting: without it a token minted by the same site key on any other page of the same
    /// site is accepted here, so a low-value form elsewhere becomes a token factory for this
    /// endpoint.
    /// </para>
    /// </summary>
    public string ExpectedAction { get; init; } = string.Empty;

    /// <summary>
    /// Hostnames a token may have been minted on. Empty switches the check off.
    /// <para>
    /// Google already checks this against the key's own domain list <i>unless</i> domain
    /// verification was turned off for the key - a common setting, because it is what lets a native
    /// app and a web app share one key. Where it is off, this list is the only thing that stops a
    /// token minted on an attacker's page with our public site key from being spent here.
    /// </para>
    /// </summary>
    public IReadOnlyList<string> AllowedHostnames { get; init; } = [];

    /// <summary>Retries after the first failure.</summary>
    [Range(1, 5)]
    public int MaxRetryAttempts { get; init; } = 1;

    /// <summary>Budget for a single attempt. Someone is staring at a spinner, so it is short.</summary>
    [Range(typeof(TimeSpan), "00:00:01", "00:00:30")]
    public TimeSpan AttemptTimeout { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>Budget for the whole call including retries and backoff.</summary>
    [Range(typeof(TimeSpan), "00:00:02", "00:01:00")]
    public TimeSpan TotalRequestTimeout { get; init; } = TimeSpan.FromSeconds(8);

    /// <summary>True when at least one secret is set, whatever the platform.</summary>
    public bool HasAnySecret =>
        !string.IsNullOrWhiteSpace(Secret)
        || !string.IsNullOrWhiteSpace(SecretWeb)
        || !string.IsNullOrWhiteSpace(SecretAndroid)
        || !string.IsNullOrWhiteSpace(SecretIos);

    /// <summary>
    /// The secret for a platform, falling back to the default one. Keys are created per platform in
    /// the provider's console, and assessing an Android token against the web key fails with a
    /// message that looks nothing like the cause - but a deployment with a single key must keep
    /// working, so an unset platform secret is a fallback and not an error.
    /// </summary>
    public string SecretFor(string? platform)
    {
        var candidate = platform?.Trim().ToLowerInvariant() switch
        {
            "android" => SecretAndroid,
            "ios" => SecretIos,
            "web" => SecretWeb,
            _ => string.Empty,
        };

        return string.IsNullOrWhiteSpace(candidate) ? Secret.Trim() : candidate.Trim();
    }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!Uri.TryCreate(BaseAddress, UriKind.Absolute, out var parsed)
            || (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps))
        {
            yield return new ValidationResult(
                $"{SectionName}:{nameof(BaseAddress)} must be an absolute http or https URI.",
                [nameof(BaseAddress)]);
        }
        else if (!parsed.AbsolutePath.EndsWith('/'))
        {
            // Same trap as the notification client's: Uri resolution replaces the last segment of
            // the base path, so a missing trailing slash silently posts the secret at the wrong
            // path and the first symptom is an HTML 404 that will not parse as JSON.
            yield return new ValidationResult(
                $"{SectionName}:{nameof(BaseAddress)} must end with '/'. Without it, Uri resolution "
                + "drops the last path segment and the request goes to the wrong endpoint with no "
                + "error anywhere.",
                [nameof(BaseAddress)]);
        }

        if (string.IsNullOrWhiteSpace(VerifyPath)
            || VerifyPath.StartsWith('/')
            || Uri.IsWellFormedUriString(VerifyPath, UriKind.Absolute))
        {
            yield return new ValidationResult(
                $"{SectionName}:{nameof(VerifyPath)} must be a relative path with no leading '/': a "
                + $"rooted or absolute value discards the path component of {nameof(BaseAddress)}.",
                [nameof(VerifyPath)]);
        }

        if (AttemptTimeout >= TotalRequestTimeout)
        {
            yield return new ValidationResult(
                $"{SectionName}:{nameof(AttemptTimeout)} must be strictly less than "
                + $"{nameof(TotalRequestTimeout)}; if one attempt can consume the whole budget then "
                + $"{nameof(MaxRetryAttempts)} is configuration that can never take effect.",
                [nameof(AttemptTimeout), nameof(TotalRequestTimeout)]);
        }

        foreach (var hostname in AllowedHostnames)
        {
            if (string.IsNullOrWhiteSpace(hostname))
            {
                yield return new ValidationResult(
                    $"{SectionName}:{nameof(AllowedHostnames)} must not contain a blank entry - it "
                    + "would match nothing and reads like the check is off when it is not.",
                    [nameof(AllowedHostnames)]);
            }
        }
    }
}

/// <summary>
/// The real reCAPTCHA adapter: a form POST to the provider's <c>siteverify</c> endpoint with the
/// deployment's secret, and the three checks that turn its answer into a verdict.
/// <para>
/// There is no retry loop, no backoff and no timeout logic in this class. All of it lives in the
/// standard resilience handler configured in <c>DependencyInjection</c>, exactly as for the
/// notification client, so what is left here is the judgement: what the provider said, and whether
/// that is good enough.
/// </para>
/// <para>
/// <b>A low score is a decision, not a failure.</b> The three checks below - token validity,
/// expected action, score threshold - are the provider answering the question it was asked, and
/// each of them produces <c>Passed = false</c>. Only the cases where nobody answered at all become
/// exceptions, and none of them can be mistaken for a pass. That asymmetry is the whole contract:
/// <b>a CAPTCHA that could not be verified must never pass</b> (docs/architecture.md draws
/// fail-open at protective counters, not at gates), while a CAPTCHA that was verified and found
/// wanting is ordinary traffic and must not page anyone.
/// </para>
/// <para>
/// <b>The secret never leaves this class.</b> It goes into a form body, never into a URL (query
/// strings are logged by every proxy on the path), never into a log line, and never into an
/// exception message - <see cref="AppException"/> messages are rendered into the response verbatim.
/// </para>
/// </summary>
public sealed class RecaptchaClient(
    HttpClient httpClient,
    IOptions<RecaptchaOptions> options,
    ILogger<RecaptchaClient> logger) : ICaptchaVerifier
{
    /// <summary>
    /// siteverify error codes that mean <b>our</b> credentials or request are wrong, not the
    /// client's token. They are a deployment defect and must not be reported to the caller as a
    /// failed CAPTCHA - that would loop a blameless user forever on a challenge they cannot pass.
    /// </summary>
    private static readonly string[] OurFaultErrorCodes =
    [
        "missing-input-secret",
        "invalid-input-secret",
        "bad-request",
    ];

    private const string NotConfiguredMessage =
        "Captcha verification is not configured on this deployment: a Recaptcha secret "
        + "(Recaptcha:Secret, or one of Recaptcha:SecretWeb / SecretAndroid / SecretIos) must be supplied.";

    private const string UpstreamUnavailableMessage =
        "The verification challenge could not be checked because the provider is unavailable.";

    private readonly RecaptchaOptions _options = options.Value;

    /// <inheritdoc />
    public bool IsConfigured => _options.HasAnySecret;

    /// <inheritdoc />
    public async Task<CaptchaAssessment> AssessAsync(
        CaptchaAssessmentRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var secret = _options.SecretFor(request.Platform);

        if (string.IsNullOrEmpty(secret))
        {
            // Error, not warning: on a deployment that routes this endpoint, every request here is
            // a user who was told to solve a CAPTCHA and now cannot finish. The message names the
            // configuration section so the fix is one search away.
            logger.LogError(
                "A CAPTCHA assessment was requested for platform {Platform}, but no {Section} secret "
                + "is configured on this deployment, so no token can be verified.",
                request.Platform,
                RecaptchaOptions.SectionName);

            // 500 NOT_CONFIGURED, not INTERNAL_ERROR: nothing upstream failed (nothing upstream was
            // asked, so it is not a 502 either) and this is our missing secret rather than a code
            // defect. NOT_CONFIGURED with the section named in the detail is the contract every
            // other optional capability answers with (see ErrorCodes.NotConfigured and the failure-
            // isolation rule in docs/architecture.md) - it points the operator at the key store
            // instead of at the source, which INTERNAL_ERROR does not.
            throw new AppException(ErrorCodes.NotConfigured, NotConfiguredMessage, 500);
        }

        var payload = await PostAsync(secret, request, cancellationToken).ConfigureAwait(false);

        return Judge(payload, request);
    }

    /// <summary>
    /// One form POST, and the transport outcome turned into the error contract - the same 5xx/4xx
    /// split the notification client makes, for the same reason: a 5xx is the provider's fault and
    /// a 4xx is ours, and reporting ours as 502 sends the page to the wrong on-call.
    /// </summary>
    private async Task<SiteVerifyResponse> PostAsync(
        string secret,
        CaptchaAssessmentRequest request,
        CancellationToken cancellationToken)
    {
        // The resilience handler re-sends this same message on every attempt, so the content has to
        // be re-readable. FormUrlEncodedContent buffers into a byte array and is; a StreamContent
        // would fail on the second attempt.
        var fields = new List<KeyValuePair<string, string>>(3)
        {
            new("secret", secret),
            new("response", request.ProviderToken),
        };

        if (!string.IsNullOrWhiteSpace(request.ClientIpAddress))
        {
            fields.Add(new KeyValuePair<string, string>("remoteip", request.ClientIpAddress));
        }

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, _options.VerifyPath)
        {
            Content = new FormUrlEncodedContent(fields),
        };

        using var response = await SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);

        var status = (int)response.StatusCode;

        if (!response.IsSuccessStatusCode)
        {
            if (status >= 500 || status is 408 or 429)
            {
                logger.LogError("reCAPTCHA siteverify answered {StatusCode}.", status);
                throw new UpstreamException(ErrorCodes.UpstreamUnavailable, UpstreamUnavailableMessage);
            }

            logger.LogError(
                "reCAPTCHA siteverify rejected our request with {StatusCode}. A 4xx here is our bug, "
                + "not theirs - the form we sent is wrong.",
                status);

            throw new AppException(ErrorCodes.InternalError, NotConfiguredMessage, 500);
        }

        try
        {
            return await response.Content.ReadFromJsonAsync<SiteVerifyResponse>(cancellationToken)
                       .ConfigureAwait(false)
                   ?? throw Unreadable(null);
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or NotSupportedException or HttpRequestException)
        {
            // A 200 whose body is not the JSON we expect is an outage shape, not a verdict: a
            // captive portal, a proxy error page, a regional block. It must not read as a pass.
            throw Unreadable(ex);
        }
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage httpRequest,
        CancellationToken cancellationToken)
    {
        try
        {
            return await httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw Unreachable(ex);
        }
        catch (ExecutionRejectedException ex)
        {
            // The pipeline's own verdict: the total-request timeout elapsed, the circuit is open,
            // or the call was shed. None of these derives from OperationCanceledException, so the
            // catch below would not see them.
            throw Unreachable(ex);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw Unreachable(ex);
        }
    }

    /// <summary>
    /// The three checks, in the order that makes a log line useful: is the token real, was it
    /// minted for what we asked, and is it good enough.
    /// </summary>
    private CaptchaAssessment Judge(SiteVerifyResponse payload, CaptchaAssessmentRequest request)
    {
        if (!payload.Success)
        {
            return FromErrorCodes(payload.ErrorCodes);
        }

        if (!IsOriginAllowed(payload))
        {
            // Warning, not error: this is what the check exists to catch. The hostname is the
            // provider's own report and is safe to log; the token is not logged anywhere.
            logger.LogWarning(
                "reCAPTCHA token was minted on hostname {Hostname}, which is not in "
                + "{Section}:{Setting}.",
                payload.Hostname,
                RecaptchaOptions.SectionName,
                nameof(RecaptchaOptions.AllowedHostnames));

            return CaptchaAssessment.Fail("hostname not allowed", payload.Score);
        }

        var expectedAction = _options.ExpectedAction.Trim();

        if (expectedAction.Length > 0
            && !string.Equals(payload.Action, expectedAction, StringComparison.Ordinal))
        {
            logger.LogWarning(
                "reCAPTCHA action mismatch: the token reports {ActualAction}, expected {ExpectedAction}.",
                payload.Action,
                expectedAction);

            return CaptchaAssessment.Fail("action mismatch", payload.Score);
        }

        // Score is absent for a v2 checkbox key. Absent is not zero: applying the threshold to a
        // key that produces no score would refuse every token it ever issues.
        if (_options.MinScore > 0 && payload.Score is { } score && score < _options.MinScore)
        {
            logger.LogInformation(
                "reCAPTCHA scored {Score} for platform {Platform}, below the {Threshold} threshold.",
                score.ToString("0.00", CultureInfo.InvariantCulture),
                request.Platform,
                _options.MinScore.ToString("0.00", CultureInfo.InvariantCulture));

            // Information, not warning: a low score is the system working. The rate of these lines
            // is a tuning signal, not an incident, and logging it louder trains everyone to ignore
            // the level that does mean something.
            return CaptchaAssessment.Fail("score below threshold", score);
        }

        return CaptchaAssessment.Pass(payload.Score);
    }

    /// <summary>
    /// Splits <c>success: false</c> into "the client's token is no good" and "our credentials are
    /// no good". Anything unrecognised falls on the refusing side, because a verdict this code
    /// cannot read is not a verdict.
    /// </summary>
    private CaptchaAssessment FromErrorCodes(IReadOnlyList<string>? errorCodes)
    {
        var codes = errorCodes ?? [];

        if (codes.Any(code => OurFaultErrorCodes.Contains(code, StringComparer.Ordinal)))
        {
            logger.LogError(
                "reCAPTCHA refused our own credentials or request shape: {ErrorCodes}. This is a "
                + "{Section} configuration defect, not a failed challenge.",
                string.Join(", ", codes),
                RecaptchaOptions.SectionName);

            throw new AppException(ErrorCodes.InternalError, NotConfiguredMessage, 500);
        }

        logger.LogInformation(
            "reCAPTCHA rejected the client token: {ErrorCodes}.",
            codes.Count > 0 ? string.Join(", ", codes) : "no error code reported");

        return CaptchaAssessment.Fail("provider rejected the token");
    }

    /// <summary>
    /// Checks where the token was minted against <see cref="RecaptchaOptions.AllowedHostnames"/>.
    /// <para>
    /// A native-app token carries <c>apk_package_name</c> and no hostname at all. Refusing it
    /// because the field is absent would break every mobile client the moment somebody pins the web
    /// hostname list, so an absent hostname cannot be ruled on here - but it is not silent either:
    /// the operator who configured an allow-list has to be able to see that some of their traffic
    /// is not covered by it, otherwise the setting reads as closed while it is half open.
    /// </para>
    /// </summary>
    private bool IsOriginAllowed(SiteVerifyResponse payload)
    {
        if (_options.AllowedHostnames.Count == 0)
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(payload.Hostname))
        {
            logger.LogWarning(
                "A reCAPTCHA token reported no hostname (native package {ApkPackageName}), so "
                + "{Section}:{Setting} could not be applied to it. Hostname pinning covers web "
                + "tokens only.",
                payload.ApkPackageName ?? "unreported",
                RecaptchaOptions.SectionName,
                nameof(RecaptchaOptions.AllowedHostnames));

            return true;
        }

        return _options.AllowedHostnames.Any(
            allowed => string.Equals(allowed.Trim(), payload.Hostname, StringComparison.OrdinalIgnoreCase));
    }

    private UpstreamException Unreachable(Exception cause)
    {
        logger.LogError(cause, "reCAPTCHA siteverify is unreachable.");

        return new UpstreamException(ErrorCodes.UpstreamUnavailable, UpstreamUnavailableMessage, cause);
    }

    private UpstreamException Unreadable(Exception? cause)
    {
        logger.LogError(cause, "reCAPTCHA siteverify answered with a body that is not a verdict.");

        return new UpstreamException(ErrorCodes.UpstreamUnavailable, UpstreamUnavailableMessage, cause);
    }

    /// <summary>
    /// The siteverify response, as far as this adapter judges on it. The wire names are snake-case
    /// and one of them is hyphenated, which no naming policy produces - hence the explicit
    /// attributes.
    /// <para>
    /// siteverify also returns <c>challenge_ts</c>. It is not modelled, deliberately: a property
    /// nothing reads looks like a freshness check and is not one, and there is nothing for it to
    /// do - the provider already reports a stale or replayed token as
    /// <c>timeout-or-duplicate</c> with <c>success: false</c>, so a token that reaches
    /// <see cref="Judge"/> with <c>success: true</c> is fresh by the provider's own account.
    /// </para>
    /// </summary>
    private sealed record SiteVerifyResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        /// <summary>v3 only. Null from a v2 checkbox key, which is why it is nullable.</summary>
        [JsonPropertyName("score")]
        public double? Score { get; init; }

        [JsonPropertyName("action")]
        public string? Action { get; init; }

        [JsonPropertyName("hostname")]
        public string? Hostname { get; init; }

        [JsonPropertyName("apk_package_name")]
        public string? ApkPackageName { get; init; }

        [JsonPropertyName("error-codes")]
        public IReadOnlyList<string>? ErrorCodes { get; init; }
    }
}
