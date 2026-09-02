namespace UserSvc.Api.Middleware;

/// <summary>
/// Configuration for <see cref="RequestContextMiddleware"/>.
/// <para>
/// Every setting has a working default and nothing here is required, which is why the section is
/// bound without <c>ValidateOnStart</c>: a deployment that does not carry it boots and behaves
/// exactly as the service did before this middleware existed.
/// </para>
/// </summary>
public sealed class RequestContextOptions
{
    public const string SectionName = "RequestContext";

    /// <summary>
    /// What a deployment that does not carry the section gets, and what one whose section will not
    /// bind falls back to. Named rather than implied, because "the defaults" is the documented
    /// degradation of <see cref="RequestContextMiddleware"/> and a degradation nobody can point at
    /// is not one.
    /// </summary>
    public static RequestContextOptions Defaults { get; } = new();

    /// <summary>
    /// Path prefixes on which <c>X-Platform</c>, <c>X-Device-ID</c>, <c>X-Request-ID</c> and
    /// <c>X-Language</c> are <b>mandatory</b>, answering <c>MISSING_HEADER</c> when one is absent.
    /// <para>
    /// <b>Empty by default, and that is a decision rather than an oversight.</b> The Go service
    /// applied this gate to every <c>/api/v1</c> route, so its clients all send the four headers.
    /// Turning it on here before those clients exist would refuse every request this service
    /// currently serves — one missing capability breaking everything except itself, which is the
    /// failure this repository has already had three times. Set it to <c>["/api/v1"]</c> in the
    /// deployment whose clients are known to send them, and the Go behaviour is back.
    /// </para>
    /// <para>
    /// It is a prefix list rather than a single flag because the gate never applied uniformly even
    /// in Go: <c>/health</c>, <c>/metrics</c> and the service-to-service group were exempt there
    /// too. Here the OAuth token endpoint has to be exempt as well — an OAuth client answers
    /// <c>error</c> / <c>error_description</c>, not ProblemDetails, and would have no idea what a
    /// <c>MISSING_HEADER</c> body meant.
    /// </para>
    /// </summary>
    public IReadOnlyList<string> RequireDeviceHeadersFor { get; init; } = [];

    /// <summary>
    /// Whether to answer <c>Content-Language</c> with the locale that was actually selected.
    /// <para>
    /// On by default: the negotiation has three inputs and one output, and a client that gets
    /// English after asking for Thai deserves to be told which language it is looking at rather than
    /// having to guess from the prose.
    /// </para>
    /// </summary>
    public bool EmitContentLanguage { get; init; } = true;
}
