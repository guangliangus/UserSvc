using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;

namespace BuildingBlocks.Web.ProblemDetails;

public static class ProblemDetailsExtensions
{
    /// <summary>
    /// RFC 9457 everywhere: exceptions via <see cref="MsvcExceptionHandler"/>, framework-produced
    /// problems (404/405/415…) enriched with traceId. Success responses are never wrapped in an
    /// envelope — DTOs (or PagedResult) go out as-is; only errors use ProblemDetails.
    /// Pair with app.UseExceptionHandler() and app.UseStatusCodePages().
    /// </summary>
    public static IServiceCollection AddMsvcProblemDetails(this IServiceCollection services)
    {
        services.AddProblemDetails(options =>
            options.CustomizeProblemDetails = context =>
            {
                // Assigned, not TryAdd'd, and deliberately the bare 32-hex trace id. The framework's
                // own writers stamp traceId with Activity.Current.Id — the whole
                // "00-<trace>-<span>-01" traceparent — before this callback runs, so a TryAdd is a
                // silent no-op for every problem MsvcExceptionHandler did not build itself (404,
                // 405, StatusCodePages), and the published value is a string no trace backend's
                // search box accepts. The bare id is also what Serilog renders as {TraceId}: one
                // value off a support ticket both greps the logs and opens the trace.
                context.ProblemDetails.Extensions["traceId"] =
                    Activity.Current?.TraceId.ToString() ?? context.HttpContext.TraceIdentifier;
                context.ProblemDetails.Instance ??= context.HttpContext.Request.Path;
            });
        services.AddExceptionHandler<MsvcExceptionHandler>();
        return services;
    }
}
