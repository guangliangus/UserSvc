namespace UserSvc.Application.Features.RiskControl;

/// <summary>
/// Hand a provider token in and get a one-time bypass token back.
/// <para>
/// The target and target type are here, and not derivable from anything else, because the token
/// this mints is <b>bound</b> to them: a CAPTCHA solved for one address must not unblock another,
/// or one solved challenge would be a reusable bypass for the whole address space.
/// </para>
/// </summary>
public sealed record CaptchaVerifyRequest
{
    /// <summary>The opaque token the client's CAPTCHA SDK produced. Named <c>answer</c> in the Go
    /// contract; kept as <c>Answer</c> so the two services speak the same word for it.</summary>
    public string Answer { get; init; } = string.Empty;

    /// <summary>The same phone number or email address the following send-code request will use.</summary>
    public string Target { get; init; } = string.Empty;

    /// <summary>See <c>VerificationTargetTypes</c>: <c>email</c> or <c>phone</c>.</summary>
    public string TargetType { get; init; } = string.Empty;
}

/// <summary>
/// The bypass token, returned exactly once. Only its hash is stored, so a client that loses this
/// value has to solve another CAPTCHA - there is nothing to look it up from.
/// </summary>
public sealed record CaptchaVerifyResponse
{
    /// <summary>Prefixed <c>cpt_</c> so a value found in a log or a bug report is recognisable for
    /// what it is: a single-use credential that skips the send-code throttle.</summary>
    public required string CaptchaToken { get; init; }

    /// <summary>
    /// Seconds until the token stops being redeemable. An integer count rather than an instant
    /// because it is a duration - the client counts down with it - and because <c>expires_in</c>
    /// seconds is what the Go contract and every OAuth-shaped client already expect.
    /// </summary>
    public required int ExpiresIn { get; init; }
}

/// <summary>
/// The per-request facts the CAPTCHA path needs that are not in the payload. Passed explicitly
/// rather than read from an ambient context, so the application layer stays testable with no
/// request in flight.
/// </summary>
/// <param name="DeviceId">
/// The <c>X-Device-ID</c> header, or empty. Client-reported and forgeable: it binds the token and
/// feeds counting, never an authorization decision. Empty binds the token to "no device", which is
/// a value the send-code path can match - not a wildcard.
/// </param>
/// <param name="Platform">
/// The <c>X-Platform</c> header: <c>ios</c>, <c>android</c> or <c>web</c>. Provider keys are issued
/// per platform, so assessing a mobile token against the web key fails for a reason that looks
/// nothing like the cause.
/// </param>
/// <param name="Language">The <c>X-Language</c> header. Only consulted when the deployment has no
/// region configured.</param>
/// <param name="ClientIpAddress">Peer address, forwarded to the provider as an assessment signal.
/// Null or empty when the server could not determine it.</param>
/// <param name="UserAgent">Caller's user agent, same purpose.</param>
public sealed record CaptchaRequestContext(
    string DeviceId,
    string Platform,
    string Language,
    string? ClientIpAddress,
    string? UserAgent);

/// <summary>
/// Which provider assesses a token. The deployment's own region is the source of truth - a CN
/// deployment cannot always reach the vendor an overseas one uses - and the request's language is
/// only a fallback for a deployment that never said.
/// </summary>
public static class CaptchaRegions
{
    public const string Overseas = "overseas";
    public const string Cn = "cn";

    /// <summary>The <c>X-Language</c> value that means "this caller is in the CN region" when the
    /// deployment did not say which region it is.</summary>
    private const string ChineseLanguage = "zh-CN";

    public static bool IsKnown(string? region) =>
        string.Equals(region, Overseas, StringComparison.OrdinalIgnoreCase)
        || string.Equals(region, Cn, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Resolves the region for one request.
    /// <para>
    /// A configured region always wins, including <c>overseas</c>: a deployment that says it is
    /// overseas does not become a CN deployment because one caller asked in Chinese. The language
    /// fallback exists only for a deployment that configured nothing, where guessing from the
    /// request beats defaulting every caller to one vendor.
    /// </para>
    /// </summary>
    public static string Resolve(string? appRegion, string? language)
    {
        if (IsKnown(appRegion))
        {
            return appRegion!.Trim().ToLowerInvariant();
        }

        return string.Equals(language?.Trim(), ChineseLanguage, StringComparison.OrdinalIgnoreCase)
            ? Cn
            : Overseas;
    }
}

/// <summary>
/// The client platforms a provider key can be issued for. Lowercase on the wire, because that is
/// what the <c>X-Platform</c> header carries.
/// </summary>
public static class CaptchaPlatforms
{
    public const string Web = "web";
    public const string Android = "android";
    public const string Ios = "ios";

    /// <summary>
    /// Trims and lowercases, and answers <see cref="Web"/> for anything absent or unrecognised.
    /// <para>
    /// Unrecognised is not an error here on purpose. The platform only selects which provider key
    /// assesses the token, and the adapter falls back to the default key when no key exists for the
    /// platform - so a new client platform nobody has configured yet still gets a real assessment
    /// rather than a 400 telling it to be a different kind of phone.
    /// </para>
    /// </summary>
    public static string Normalize(string? platform)
    {
        var normalized = platform?.Trim().ToLowerInvariant();

        return normalized switch
        {
            Android => Android,
            Ios => Ios,
            _ => Web,
        };
    }
}
