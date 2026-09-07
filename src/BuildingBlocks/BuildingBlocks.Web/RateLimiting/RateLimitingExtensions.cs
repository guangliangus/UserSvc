using System.Diagnostics;
using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace BuildingBlocks.Web.RateLimiting;

public static class RateLimitingExtensions
{
    /// <summary>
    /// Config-driven rate limiting: named policies under "RateLimiting:Policies" (fixed/sliding
    /// window, token bucket, concurrency) partitioned per caller or IP, applied per endpoint via
    /// [EnableRateLimiting("name")] plus an optional global policy. Rejections are 429
    /// ProblemDetails with Retry-After when known.
    /// </summary>
    public static IServiceCollection AddMsvcRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<RateLimitingOptions>()
            .Bind(configuration.GetSection(RateLimitingOptions.SectionName))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<RateLimitingOptions>, RateLimitingOptionsValidator>();

        var options = configuration.GetSection(RateLimitingOptions.SectionName).Get<RateLimitingOptions>()
            ?? new RateLimitingOptions();

        services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.OnRejected = static async (context, cancellationToken) =>
            {
                var response = context.HttpContext.Response;
                response.StatusCode = StatusCodes.Status429TooManyRequests;
                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    response.Headers.RetryAfter =
                        ((int)retryAfter.TotalSeconds).ToString(CultureInfo.InvariantCulture);
                }

                await response.WriteAsJsonAsync(new
                {
                    status = StatusCodes.Status429TooManyRequests,
                    title = "Too many requests.",
                    errorCode = "rate_limited",
                    traceId = Activity.Current?.TraceId.ToString() ?? context.HttpContext.TraceIdentifier,
                }, options: null, contentType: "application/problem+json", cancellationToken);
            };

            foreach (var (name, policy) in options.Policies)
            {
                limiter.AddPolicy(name, httpContext => CreatePartition(httpContext, name, policy));
            }

            if (options.GlobalPolicy is { Length: > 0 } globalName)
            {
                if (!options.Policies.TryGetValue(globalName, out var globalPolicy))
                {
                    throw new InvalidOperationException(
                        $"RateLimiting:GlobalPolicy '{globalName}' has no matching entry under RateLimiting:Policies.");
                }

                limiter.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
                    httpContext => CreatePartition(httpContext, globalName, globalPolicy));
            }
        });

        return services;
    }

    /// <summary>No-op when "RateLimiting:Enabled" is false, so the middleware can stay in the pipeline unconditionally.</summary>
    public static WebApplication UseMsvcRateLimiting(this WebApplication app)
    {
        var options = app.Services.GetRequiredService<IOptions<RateLimitingOptions>>().Value;
        if (options.Enabled)
        {
            app.UseRateLimiter();
        }

        return app;
    }

    private static RateLimitPartition<string> CreatePartition(
        HttpContext httpContext,
        string policyName,
        RateLimitPolicyOptions policy)
    {
        var key = $"{policyName}:{ResolvePartitionKey(httpContext, policy.PartitionBy)}";

        return policy.Type switch
        {
            RateLimitPolicyType.SlidingWindow => RateLimitPartition.GetSlidingWindowLimiter(key, _ =>
                new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = policy.PermitLimit,
                    Window = TimeSpan.FromSeconds(policy.WindowSeconds),
                    SegmentsPerWindow = policy.SegmentsPerWindow,
                    QueueLimit = policy.QueueLimit,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                }),

            RateLimitPolicyType.TokenBucket => RateLimitPartition.GetTokenBucketLimiter(key, _ =>
                new TokenBucketRateLimiterOptions
                {
                    TokenLimit = policy.PermitLimit,
                    TokensPerPeriod = policy.TokensPerPeriod,
                    ReplenishmentPeriod = TimeSpan.FromSeconds(policy.ReplenishmentPeriodSeconds),
                    QueueLimit = policy.QueueLimit,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                }),

            RateLimitPolicyType.Concurrency => RateLimitPartition.GetConcurrencyLimiter(key, _ =>
                new ConcurrencyLimiterOptions
                {
                    PermitLimit = policy.PermitLimit,
                    QueueLimit = policy.QueueLimit,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                }),

            _ => RateLimitPartition.GetFixedWindowLimiter(key, _ =>
                new FixedWindowRateLimiterOptions
                {
                    PermitLimit = policy.PermitLimit,
                    Window = TimeSpan.FromSeconds(policy.WindowSeconds),
                    QueueLimit = policy.QueueLimit,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                }),
        };
    }

    private static string ResolvePartitionKey(HttpContext httpContext, RateLimitPartitionStrategy strategy)
    {
        return strategy switch
        {
            RateLimitPartitionStrategy.None => "*",
            RateLimitPartitionStrategy.Ip => Ip(httpContext),
            RateLimitPartitionStrategy.Caller =>
                httpContext.User.FindFirst("azp")?.Value
                ?? httpContext.User.FindFirst("client_id")?.Value
                ?? httpContext.User.FindFirst("sub")?.Value
                ?? Ip(httpContext),
            _ => "*",
        };

        static string Ip(HttpContext ctx) => ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}
