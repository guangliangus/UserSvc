using System.Diagnostics;

namespace UserSvc.Api.Middleware;

/// <summary>
/// Stamps <c>X-Trace-ID</c> on every traced response: the bare 32-hex W3C trace id, the same value
/// ProblemDetails already publishes as <c>traceId</c> and Serilog writes as <c>{TraceId}</c>.
/// <para>
/// This is the one observable side effect of the Go <c>TraceMiddleware</c> that .NET does not
/// already provide. OpenTelemetry creates the server span and propagates the incoming
/// <c>traceparent</c> for us; what it does not do is hand the value back to the caller. Without
/// this header a client can only quote a trace id it can find in a response body, which means
/// never on a success and never on the 401s and 403s written by middleware.
/// </para>
/// <para>
/// <b>Placement:</b> beside <see cref="RequestContextMiddleware"/>, after
/// <c>UseStatusCodePages()</c>. It only registers a response callback, so it cannot swallow an
/// exception and its position is not load-bearing — but the callback has to be registered before
/// anything writes the first byte, and everything that writes a body in this pipeline is deeper
/// than this point or unwinds through it.
/// </para>
/// <para>
/// <c>/health</c> and <c>/metrics</c> are skipped, exactly as the Go middleware skipped them: they
/// are excluded from tracing, so there is no id to stamp and stamping the ambient one would
/// advertise a span that no backend holds.
/// </para>
/// </summary>
public sealed class TraceHeaderMiddleware(RequestDelegate next)
{
    /// <summary>The header name. Public because it is part of the response contract.</summary>
    public const string HeaderName = "X-Trace-ID";

    private static readonly string[] Untraced = ["/health", "/metrics"];

    public Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var path = context.Request.Path.Value ?? string.Empty;

        foreach (var prefix in Untraced)
        {
            if (PathPrefix.Matches(path, prefix))
            {
                return next(context);
            }
        }

        // Stamped on the way out: the header must be set before the response starts, and the
        // current activity is already the server span by the time any of this runs.
        context.Response.OnStarting(
            static state =>
            {
                var response = (HttpResponse)state;
                var traceId = Activity.Current?.TraceId.ToString();

                if (!string.IsNullOrEmpty(traceId) && !response.Headers.ContainsKey(HeaderName))
                {
                    response.Headers[HeaderName] = traceId;
                }

                return Task.CompletedTask;
            },
            context.Response);

        return next(context);
    }
}
