using BuildingBlocks.Core.Abstractions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace BuildingBlocks.Web.Auth;

public static class AuthExtensions
{
    /// <summary>
    /// JWT bearer against the configured OIDC authority. Claims are NOT remapped to the legacy
    /// SOAP names (MapInboundClaims=false): use "sub", "azp", "scope" directly in policies.
    /// Also switches the audit actor to the authenticated caller.
    /// </summary>
    public static IServiceCollection AddMsvcJwtAuth(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<AuthorizationOptions>? configureAuthorization = null)
    {
        services.AddOptions<AuthOptions>()
            .Bind(configuration.GetSection(AuthOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        var options = configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>();
        if (options is null || string.IsNullOrWhiteSpace(options.Authority))
        {
            throw new InvalidOperationException($"'{AuthOptions.SectionName}:Authority' is not configured.");
        }

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(jwt =>
            {
                jwt.Authority = options.Authority;
                jwt.RequireHttpsMetadata = options.RequireHttpsMetadata;
                jwt.MapInboundClaims = false;
                jwt.TokenValidationParameters.ValidateAudience = true;
                jwt.TokenValidationParameters.ValidAudience = options.Audience;
                if (options.ValidIssuers is { Length: > 0 })
                {
                    jwt.TokenValidationParameters.ValidIssuers = options.ValidIssuers;
                }
            });

        if (configureAuthorization is null)
        {
            services.AddAuthorization();
        }
        else
        {
            services.AddAuthorization(configureAuthorization);
        }

        services.AddHttpContextAccessor();
        services.Replace(ServiceDescriptor.Scoped<ICurrentActor, HttpContextCurrentActor>());

        return services;
    }
}
