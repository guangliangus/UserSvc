using Asp.Versioning;
using Microsoft.Extensions.DependencyInjection;

namespace BuildingBlocks.Web.Versioning;

public static class ApiVersioningExtensions
{
    /// <summary>
    /// URL-segment versioning (/api/v1/...), default v1, supported versions reported via
    /// api-supported-versions. Also registers the version-aware OpenAPI documents
    /// (one per API version, named by the group format: v1, v2, ...).
    /// </summary>
    public static IServiceCollection AddMsvcApiVersioning(this IServiceCollection services)
    {
        services.AddApiVersioning(options =>
            {
                options.DefaultApiVersion = new ApiVersion(1.0);
                options.AssumeDefaultVersionWhenUnspecified = true;
                options.ReportApiVersions = true;
                options.ApiVersionReader = new UrlSegmentApiVersionReader();
            })
            .AddMvc()
            .AddApiExplorer(options =>
            {
                options.GroupNameFormat = "'v'VVV";
                options.SubstituteApiVersionInUrl = true;
            })
            .AddOpenApi();

        return services;
    }
}
