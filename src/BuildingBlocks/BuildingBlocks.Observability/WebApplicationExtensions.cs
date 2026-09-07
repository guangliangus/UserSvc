using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Serilog;
using Serilog.Events;

namespace BuildingBlocks.Observability;

public static class WebApplicationExtensions
{
    /// <summary>
    /// Serilog request logging (path, status, elapsed) with route/caller enrichment.
    /// Health and metrics probes log at Verbose so they don't drown application logs.
    /// Register it OUTSIDE UseExceptionHandler: placed inside, it sees the exception still in
    /// flight and records a handled 4xx as a 500, and every SLO dashboard built on the request
    /// log then reads the service's own validation failures as its own outage.
    /// </summary>
    public static WebApplication UseMsvcRequestLogging(this WebApplication app)
    {
        app.UseSerilogRequestLogging(options =>
        {
            options.GetLevel = (httpContext, _, exception) =>
                exception is not null || httpContext.Response.StatusCode >= 500
                    ? LogEventLevel.Error
                    : WebApplicationBuilderExtensions.IsInfrastructurePath(httpContext.Request.Path.Value)
                        ? LogEventLevel.Verbose
                        : LogEventLevel.Information;

            options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
            {
                diagnosticContext.Set("route", httpContext.GetEndpoint()?.DisplayName ?? "unmatched");
                var caller = httpContext.User.FindFirst("azp")?.Value
                    ?? httpContext.User.FindFirst("client_id")?.Value
                    ?? httpContext.User.FindFirst("sub")?.Value;
                if (caller is not null)
                {
                    diagnosticContext.Set("caller", caller);
                }
            };
        });
        return app;
    }

    /// <summary>
    /// K8s-aligned endpoints: <see cref="MapMsvcHealthProbes"/> plus <see cref="MapMsvcMetrics"/>.
    /// Hosts with their own probe layout call the two halves separately.
    /// </summary>
    public static WebApplication MapMsvcObservabilityEndpoints(this WebApplication app)
    {
        app.MapMsvcHealthProbes();
        app.MapMsvcMetrics();
        return app;
    }

    /// <summary>
    /// The three probes: /health/startup runs checks tagged "startup", /health/live is a process
    /// self-check only — neither may aggregate external dependencies (a broken DB would otherwise
    /// restart every pod); /health/ready aggregates checks tagged "ready" (postgres/redis/rabbitmq).
    /// All three write the same diagnosable body: aggregate status plus one entry per check, sorted
    /// by name, with the description the check chose to publish. The default writer answers with
    /// the single word "Unhealthy", which tells the person paged that something is wrong and
    /// nothing about what.
    /// </summary>
    public static WebApplication MapMsvcHealthProbes(this WebApplication app)
    {
        app.MapHealthChecks("/health/startup", new HealthCheckOptions
        {
            Predicate = r => r.Tags.Contains("startup"),
            ResponseWriter = WriteHealthReport,
        });
        app.MapHealthChecks("/health/live", new HealthCheckOptions
        {
            Predicate = _ => false,
            ResponseWriter = WriteHealthReport,
        });
        app.MapHealthChecks("/health/ready", new HealthCheckOptions
        {
            Predicate = r => r.Tags.Contains("ready"),
            ResponseWriter = WriteHealthReport,
        });

        return app;
    }

    /// <summary>The Prometheus scrape endpoint (/metrics). Metrics are scraped, never pushed over OTLP.</summary>
    public static WebApplication MapMsvcMetrics(this WebApplication app)
    {
        app.MapPrometheusScrapingEndpoint();
        return app;
    }

    /// <summary>
    /// Only what a check chose to say: its status, its description and how long it took. Exception
    /// messages and stack traces are deliberately not written — HealthCheckService already logs
    /// them, and a probe body is reachable by anyone who can reach the pod.
    /// </summary>
    private static Task WriteHealthReport(HttpContext context, HealthReport report)
    {
        context.Response.ContentType = "application/json";
        var payload = JsonSerializer.Serialize(new
        {
            status = report.Status.ToString(),
            totalDurationMs = report.TotalDuration.TotalMilliseconds,
            checks = report.Entries
                .OrderBy(e => e.Key, StringComparer.Ordinal)
                .Select(e => new
                {
                    name = e.Key,
                    status = e.Value.Status.ToString(),
                    description = string.IsNullOrEmpty(e.Value.Description) ? null : e.Value.Description,
                    durationMs = e.Value.Duration.TotalMilliseconds,
                })
                .ToArray(),
        }, JsonOptions);
        return context.Response.WriteAsync(payload);
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };
}
