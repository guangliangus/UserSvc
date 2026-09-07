using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace BuildingBlocks.Web.Cors;

/// <summary>Bound from "Cors". No origins configured → CORS middleware stays inactive.</summary>
public sealed class MsvcCorsOptions
{
    public const string SectionName = "Cors";
    public const string PolicyName = "msvc";

    public string[] Origins { get; set; } = [];
    public bool AllowCredentials { get; set; }
}

public static class CorsExtensions
{
    public static IServiceCollection AddMsvcCors(this IServiceCollection services, IConfiguration configuration)
    {
        var options = configuration.GetSection(MsvcCorsOptions.SectionName).Get<MsvcCorsOptions>()
            ?? new MsvcCorsOptions();
        services.AddSingleton(options);

        if (options.Origins.Length == 0)
        {
            return services;
        }

        services.AddCors(cors => cors.AddPolicy(MsvcCorsOptions.PolicyName, policy =>
        {
            policy.WithOrigins(options.Origins).AllowAnyHeader().AllowAnyMethod();
            if (options.AllowCredentials)
            {
                policy.AllowCredentials();
            }
        }));

        return services;
    }

    public static WebApplication UseMsvcCors(this WebApplication app)
    {
        var options = app.Services.GetRequiredService<MsvcCorsOptions>();
        if (options.Origins.Length > 0)
        {
            app.UseCors(MsvcCorsOptions.PolicyName);
        }

        return app;
    }
}
