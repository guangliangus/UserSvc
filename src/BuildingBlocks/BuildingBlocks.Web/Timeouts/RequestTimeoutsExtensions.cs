using System.Diagnostics;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace BuildingBlocks.Web.Timeouts;

public static class RequestTimeoutsExtensions
{
    /// <summary>
    /// Server-side request timeouts: a global default plus named policies for
    /// [RequestTimeout("name")] endpoints ([DisableRequestTimeout] opts out). Timeouts cancel
    /// HttpContext.RequestAborted, so they only bite endpoints that pass the CancellationToken
    /// down — which is the template convention anyway. On expiry the response is a 504
    /// ProblemDetails written through <see cref="IProblemDetailsService"/>, so the host's
    /// CustomizeProblemDetails (traceId, instance, localization) applies to it like to every other
    /// error. The framework middleware disables itself while a debugger is attached.
    /// </summary>
    public static IServiceCollection AddMsvcRequestTimeouts(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<MsvcRequestTimeoutsOptions>()
            .Bind(configuration.GetSection(MsvcRequestTimeoutsOptions.SectionName))
            .ValidateDataAnnotations()
            .Validate(
                o => o.Policies.Values.All(seconds => seconds is >= 1 and <= 3600),
                "RequestTimeouts:Policies values must be 1-3600 seconds.")
            .ValidateOnStart();

        var options = configuration.GetSection(MsvcRequestTimeoutsOptions.SectionName).Get<MsvcRequestTimeoutsOptions>()
            ?? new MsvcRequestTimeoutsOptions();

        services.AddRequestTimeouts(timeouts =>
        {
            timeouts.DefaultPolicy = BuildPolicy(TimeSpan.FromSeconds(options.DefaultTimeoutSeconds), options.ErrorCode);
            foreach (var (name, seconds) in options.Policies)
            {
                timeouts.AddPolicy(name, BuildPolicy(TimeSpan.FromSeconds(seconds), options.ErrorCode));
            }
        });

        return services;
    }

    /// <summary>No-op when "RequestTimeouts:Enabled" is false.</summary>
    public static WebApplication UseMsvcRequestTimeouts(this WebApplication app)
    {
        if (app.Services.GetRequiredService<IOptions<MsvcRequestTimeoutsOptions>>().Value.Enabled)
        {
            app.UseRequestTimeouts();
        }

        return app;
    }

    private static RequestTimeoutPolicy BuildPolicy(TimeSpan timeout, string errorCode) => new()
    {
        Timeout = timeout,
        TimeoutStatusCode = StatusCodes.Status504GatewayTimeout,
        WriteTimeoutResponse = context => WriteTimeoutProblemAsync(context, errorCode),
    };

    private static async Task WriteTimeoutProblemAsync(HttpContext context, string errorCode)
    {
        var problem = new Microsoft.AspNetCore.Mvc.ProblemDetails
        {
            Status = StatusCodes.Status504GatewayTimeout,
            Title = "The request timed out.",
            Instance = context.Request.Path,
        };
        problem.Extensions["errorCode"] = errorCode;

        // The middleware has already restored the original RequestAborted and set the status code
        // before invoking this callback. Prefer the host's ProblemDetails pipeline; fall back to a
        // plain write only when no writer accepts the request (content negotiation), so the client
        // still gets application/problem+json rather than an empty 504.
        var problemDetailsService = context.RequestServices.GetService<IProblemDetailsService>();
        if (problemDetailsService is not null
            && await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
            {
                HttpContext = context,
                ProblemDetails = problem,
            }))
        {
            return;
        }

        problem.Extensions["traceId"] = Activity.Current?.TraceId.ToString() ?? context.TraceIdentifier;
        await context.Response.WriteAsJsonAsync(problem, options: null, contentType: "application/problem+json");
    }
}
