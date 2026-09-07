using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using Scalar.AspNetCore;

namespace BuildingBlocks.Web.OpenApi;

public static class OpenApiExtensions
{
    /// <summary>
    /// Serves /openapi/{version}.json (one document per API version, registered by
    /// AddMsvcApiVersioning) and the Scalar UI at /scalar — non-production environments only.
    /// </summary>
    public static WebApplication MapMsvcApiDocs(this WebApplication app)
    {
        if (!app.Environment.IsProduction())
        {
            app.MapOpenApi().WithDocumentPerVersion();
            app.MapScalarApiReference();
        }

        return app;
    }
}
