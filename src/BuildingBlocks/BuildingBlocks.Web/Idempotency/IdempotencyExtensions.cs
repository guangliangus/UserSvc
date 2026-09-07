using BuildingBlocks.Core.Idempotency;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace BuildingBlocks.Web.Idempotency;

public static class IdempotencyExtensions
{
    /// <summary>
    /// Idempotency-Key support for unsafe endpoints (see <see cref="IdempotencyMiddleware"/>).
    /// Requires an <see cref="IIdempotencyStore"/> — AddMsvcRedisCaching registers the Redis one.
    /// </summary>
    public static IServiceCollection AddMsvcIdempotency(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<IdempotencyOptions>()
            .Bind(configuration.GetSection(IdempotencyOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();
        return services;
    }

    /// <summary>
    /// No-op when "Idempotency:Enabled" is false. Place after auth (the key is caller-scoped)
    /// and after rate limiting (replays still count against the caller's budget).
    /// </summary>
    public static WebApplication UseMsvcIdempotency(this WebApplication app)
    {
        if (!app.Services.GetRequiredService<IOptions<IdempotencyOptions>>().Value.Enabled)
        {
            return app;
        }

        if (app.Services.GetService<IIdempotencyStore>() is null)
        {
            throw new InvalidOperationException(
                "Idempotency needs an IIdempotencyStore. Call AddMsvcRedisCaching (or register a store), or set Idempotency:Enabled=false.");
        }

        app.UseMiddleware<IdempotencyMiddleware>();
        return app;
    }
}
