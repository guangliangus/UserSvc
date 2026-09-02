using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;

namespace UserSvc.Api.Middleware;

/// <summary>
/// Computes the request's <see cref="RequestContext"/> once, so that the locale, the device
/// identity and the client's correlation id are settled before anything can need them.
/// <para>
/// This is the port of the Go <c>DeviceInfoRequired</c> middleware, minus its global refusal. It
/// captures and normalises the same headers, but requiring them is opt-in per path prefix (see
/// <see cref="RequestContextOptions.RequireDeviceHeadersFor"/>) and off by default. Making them
/// mandatory would refuse every request the service serves today over headers no current client
/// sends — a missing capability breaking everything but itself.
/// </para>
/// <para>
/// <b>Where it goes in the pipeline, and why.</b> Immediately after
/// <c>UseStatusCodePages()</c> and before <c>UseAuthentication()</c>:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <b>Inside</b> <c>UseExceptionHandler()</c> and <c>UseStatusCodePages()</c>, because the
/// <c>MISSING_HEADER</c> refusal is thrown and has to reach the handler that turns it into
/// ProblemDetails. It also means the two response writers above it can read the negotiated locale
/// off <c>HttpContext.Items</c> while writing a body, which is the whole reason the catalogue
/// reaches a 401.
/// </description></item>
/// <item><description>
/// <b>Before</b> <c>UseAuthentication()</c>, because an authentication challenge produces its 401
/// on the way back out. Run it after authentication and the one response class that most needs a
/// translated sentence is the one class that cannot have one.
/// </description></item>
/// <item><description>
/// <b>Not</b> outermost, unlike <c>UseSerilogRequestLogging()</c>: that one must sit above the
/// exception handler to record the status the client actually received, and this one must sit below
/// it for the opposite reason — its own refusal is an ordinary 400 and must be handled, not logged
/// as an outage.
/// </description></item>
/// <item><description>
/// <b>Not</b> between authentication and authorization. That gap belongs to
/// <c>RevokedSessionMiddleware</c> and <c>BackOfficeAuthzMiddleware</c>, in that order, and both
/// are there because they read token claims. This middleware reads only headers, so it has no
/// business in a slot whose ordering is load-bearing for something else.
/// </description></item>
/// </list>
/// </summary>
public sealed class RequestContextMiddleware(RequestDelegate next)
{
    /// <summary>
    /// Paths the header requirement never applies to, whatever the configuration says.
    /// <para>
    /// The probes carry no headers by design; the OAuth endpoints answer in OAuth's error shape and
    /// must never be handed a ProblemDetails body; and the OpenAPI documents are read by a browser.
    /// </para>
    /// </summary>
    private static readonly string[] NeverRequired =
    [
        "/health",
        "/metrics",
        "/connect",
        "/.well-known",
        "/openapi",
        "/swagger",
    ];

    /// <summary>Reported once per process when the section will not bind, then suppressed - this
    /// runs on every request and a per-request error line would bury the one that matters.</summary>
    private static int _optionsFailureReported;

    public async Task InvokeAsync(
        HttpContext context,
        IOptions<RequestContextOptions> options,
        ILogger<RequestContextMiddleware> logger)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        var settings = Settings(options, logger);
        var request = RequestContextAccessor.Of(context);

        // Scope rather than a Serilog diagnostic context, so this works under any logging provider.
        // It is what puts the client's own correlation id on every line the request produces - the
        // single most useful thing to have when a client reports "request req-abc failed".
        // Opened BEFORE the header gate so that the gate's own warning is correlated too: that
        // line is the only record of a refusal whose response body names no header.
        using var scope = logger.BeginScope(new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["RequestId"] = request.RequestId,
            ["Platform"] = request.Platform,
            ["DeviceId"] = request.DeviceId,
            ["Locale"] = request.Locale,
        });

        // Only when the caller actually asked for a language. Announcing "Content-Language: en" to
        // a caller that asked for nothing would add a header to every response this service has
        // ever sent - and it would be a claim about the body that this middleware cannot check,
        // since a detail is only translated when a language was requested. Answering the question
        // that was asked, and staying silent about the one that was not, is the honest shape.
        if (settings.EmitContentLanguage && request.LocaleWasRequested)
        {
            // Registered as a callback rather than assigned: a middleware further in may have
            // already started the response by the time this one unwinds, and assigning a header
            // then throws.
            context.Response.OnStarting(
                static state =>
                {
                    var (response, locale) = ((HttpResponse, string))state;

                    if (!response.Headers.ContainsKey("Content-Language"))
                    {
                        response.Headers.ContentLanguage = locale;
                    }

                    return Task.CompletedTask;
                },
                (context.Response, request.Locale));
        }

        if (IsGated(context.Request.Path, settings.RequireDeviceHeadersFor))
        {
            RequireHeaders(request, logger);
        }

        await next(context);
    }

    /// <summary>
    /// The bound section, or the defaults when it will not bind.
    /// <para>
    /// <b>The read is here and not in a constructor, and it is guarded.</b> <c>.Value</c> is what
    /// runs binding and validation, so an eager read would make merely constructing this type throw;
    /// it is also cached, so reading it per request costs nothing. The guard is the second half of
    /// the same rule: this middleware sits in the global pipeline, so an unguarded read would let a
    /// single mistyped setting - <c>RequireDeviceHeadersFor</c> written as a scalar instead of a
    /// list, say - answer <b>every</b> request in the service with a 500. A capability that is only
    /// allowed to break itself has to degrade to its defaults here, loudly in the log and silently
    /// on the wire, because its defaults are exactly "behave as the service did before this section
    /// existed".
    /// </para>
    /// </summary>
    private static RequestContextOptions Settings(
        IOptions<RequestContextOptions> options, ILogger logger)
    {
        try
        {
            return options.Value;
        }
        catch (Exception ex)
        {
            if (Interlocked.Exchange(ref _optionsFailureReported, 1) == 0)
            {
                logger.LogError(
                    ex,
                    "The {Section} configuration section could not be bound; the header gate is off "
                    + "and Content-Language is being emitted as if the section were absent. Fix the "
                    + "section or remove it.",
                    RequestContextOptions.SectionName);
            }

            return RequestContextOptions.Defaults;
        }
    }

    private static bool IsGated(PathString path, IReadOnlyList<string> gatedPrefixes)
    {
        if (gatedPrefixes.Count == 0)
        {
            return false;
        }

        var value = path.Value ?? string.Empty;

        foreach (var exempt in NeverRequired)
        {
            if (PathPrefix.Matches(value, exempt))
            {
                return false;
            }
        }

        foreach (var prefix in gatedPrefixes)
        {
            if (PathPrefix.Matches(value, prefix))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The four-header check, refusing with one code for all four.
    /// <para>
    /// One code is faithful to the Go contract and is also right: the client's fix is the same
    /// whichever header it forgot, and naming them individually would multiply the error vocabulary
    /// for no decision the client makes differently. The log line names them, which is where an
    /// operator looks anyway - and unlike the Go original it names the language header too, whose
    /// absence was the one thing that could refuse a request without appearing in the log.
    /// </para>
    /// </summary>
    private static void RequireHeaders(RequestContext request, ILogger logger)
    {
        var missing = new List<string>(4);

        if (request.Platform.Length == 0)
        {
            missing.Add("X-Platform");
        }

        if (request.DeviceId.Length == 0)
        {
            missing.Add("X-Device-ID");
        }

        if (request.RequestId.Length == 0)
        {
            missing.Add("X-Request-ID");
        }

        if (request.RawLanguage.Length == 0)
        {
            missing.Add(RequestContextAccessor.LanguageHeader);
        }

        if (missing.Count == 0)
        {
            return;
        }

        logger.LogWarning("Missing required headers: {MissingHeaders}", string.Join(", ", missing));

        throw new BadRequestException(
            ErrorCodes.MissingHeader,
            "The request is missing headers this endpoint requires. Update the app.");
    }
}
