using System.Text.Json;
using UserSvc.Application.Features.Localization;

namespace UserSvc.Api.Middleware;

/// <summary>
/// The per-request facts every cross-cutting consumer needs and none of them should read a header
/// for: which client is calling, which device, which request id to quote in an audit row, and which
/// language to answer in.
/// <para>
/// It is a snapshot, computed once. Two places reading <c>X-Platform</c> and normalising it
/// differently is how a per-platform captcha site key gets picked for <c>iOS</c> on one code path
/// and <c>ios</c> on the next.
/// </para>
/// </summary>
public sealed record RequestContext
{
    /// <summary>The empty context: what an exempt or unrouted request has. Never null, so no
    /// consumer has to branch.</summary>
    public static RequestContext None { get; } = new();

    /// <summary><c>X-Platform</c>, trimmed and lowercased once, here. Empty when absent.</summary>
    public string Platform { get; init; } = string.Empty;

    /// <summary><c>X-Device-ID</c>, raw.</summary>
    public string DeviceId { get; init; } = string.Empty;

    /// <summary>
    /// <c>X-Device-Info</c> if it parsed as JSON, plain or percent-encoded; empty otherwise. It is
    /// diagnostic metadata and never a gate, so anything unparseable is dropped rather than
    /// refused.
    /// </summary>
    public string DeviceInfo { get; init; } = string.Empty;

    /// <summary><c>X-Request-ID</c>, raw. Empty when the client sent none — it is the client's
    /// correlation id, and inventing one would hand them an id they never saw.</summary>
    public string RequestId { get; init; } = string.Empty;

    /// <summary>
    /// The peer address, as the socket reports it.
    /// <para>
    /// <b>It is the gateway's address, not the end user's, whenever this service runs behind one</b>
    /// - nothing in this host registers <c>UseForwardedHeaders</c>, so <c>X-Forwarded-For</c> is not
    /// consulted. The Go middleware this ports read gin's <c>ClientIP()</c>, which does consult it,
    /// so this field is deliberately narrower than its ancestor and is not a drop-in source for an
    /// audit row's actor IP. Configuring the forwarded-headers middleware with the gateway in
    /// <c>KnownProxies</c> is what would close the gap, and it belongs to the host, not here.
    /// </para>
    /// </summary>
    public string ClientIp { get; init; } = string.Empty;

    /// <summary>The raw language tag the client asked for, before normalisation. Kept for logs:
    /// "the client sent zh-Hant-HK and got zh-TW" is the only way to debug a locale complaint.</summary>
    public string RawLanguage { get; init; } = string.Empty;

    /// <summary>One of the seven codes in <see cref="SupportedLocales"/>. Always populated.</summary>
    public string Locale { get; init; } = SupportedLocales.Default;

    /// <summary>
    /// Whether the client actually asked for a language this service has text in, as opposed to
    /// asking for nothing (or for Klingon) and being defaulted to English.
    /// <para>
    /// This is the distinction the Go normalizer's comment insisted on keeping, and here it decides
    /// something: error <c>detail</c> is replaced with the catalogue's sentence only when it is
    /// true. A caller that asked for no language keeps the sentence its throw site wrote, so
    /// hundreds of existing responses are untouched and nothing had to be rewritten to introduce
    /// the catalogue.
    /// </para>
    /// </summary>
    public bool LocaleWasRequested { get; init; }

    /// <summary>Which header answered, for the response's <c>Content-Language</c> and for logs.</summary>
    public LocaleSource LocaleSource { get; init; } = LocaleSource.Default;
}

/// <summary>
/// Reads and writes the request's <see cref="RequestContext"/>.
/// <para>
/// <see cref="Of"/> never returns null and never depends on middleware ordering: if
/// <see cref="RequestContextMiddleware"/> has not run for this request — an exception raised
/// outside it, a response written by a middleware that sits above it — it negotiates the locale from
/// the headers on the spot and caches that. Anything that reads this from an error path would
/// otherwise be one pipeline reshuffle away from answering in the wrong language, silently.
/// </para>
/// </summary>
public static class RequestContextAccessor
{
    private const string ItemKey = "usersvc.request-context";

    internal const string PlatformHeader = "X-Platform";
    internal const string DeviceIdHeader = "X-Device-ID";
    internal const string DeviceInfoHeader = "X-Device-Info";
    internal const string RequestIdHeader = "X-Request-ID";

    /// <summary>The explicit locale header, and the only one the Go service read.</summary>
    public const string LanguageHeader = "X-Language";

    /// <summary>The request's context, computing it if it is not there yet.</summary>
    public static RequestContext Of(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Items.TryGetValue(ItemKey, out var stored) && stored is RequestContext existing)
        {
            return existing;
        }

        var captured = Capture(context);
        context.Items[ItemKey] = captured;

        return captured;
    }

    /// <summary>The request's locale. The short form of <see cref="Of"/> for the many callers that
    /// want nothing else.</summary>
    public static string LocaleOf(HttpContext context) => Of(context).Locale;

    internal static RequestContext Capture(HttpContext context)
    {
        var headers = context.Request.Headers;
        var rawLanguage = headers[LanguageHeader].ToString();
        var language = LocaleNegotiation.Resolve(rawLanguage, headers.AcceptLanguage.ToString());

        return new RequestContext
        {
            // Normalised once, here, so every downstream consumer matches "iOS", " ios " and "WEB"
            // the same way. Doing it at each consumer is how two of them disagree.
            Platform = headers[PlatformHeader].ToString().Trim().ToLowerInvariant(),
            DeviceId = headers[DeviceIdHeader].ToString(),
            DeviceInfo = ParseDeviceInfo(headers[DeviceInfoHeader].ToString()),
            RequestId = headers[RequestIdHeader].ToString(),
            ClientIp = context.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            RawLanguage = rawLanguage,
            Locale = language.Locale,
            LocaleWasRequested = language.WasRequested,
            LocaleSource = language.Source,
        };
    }

    /// <summary>
    /// <c>X-Device-Info</c> is optional and free-form: plain JSON, or the same JSON
    /// percent-encoded because it travelled through a client that escaped it. The stored value is
    /// whichever form parsed; anything that parses as neither is dropped.
    /// </summary>
    private static string ParseDeviceInfo(string header)
    {
        if (header.Length == 0)
        {
            return string.Empty;
        }

        if (IsJsonObject(header))
        {
            return header;
        }

        var decoded = Unescape(header);

        return decoded is not null && IsJsonObject(decoded) ? decoded : string.Empty;
    }

    private static string? Unescape(string value)
    {
        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch (UriFormatException)
        {
            // A stray '%' is a malformed header, not a fault in the request being served.
            return null;
        }
    }

    /// <summary>
    /// Whether the value is a JSON <b>object</b>. The object requirement is the Go behaviour, not
    /// an extra rule: Go unmarshalled the header into a map, so <c>X-Device-Info: 42</c> - a
    /// perfectly valid JSON document - was dropped there and has to be dropped here too. Accepting
    /// it would store a scalar in a field every reader treats as an object.
    /// </summary>
    private static bool IsJsonObject(string value)
    {
        try
        {
            using var parsed = JsonDocument.Parse(value);

            return parsed.RootElement.ValueKind == JsonValueKind.Object;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
