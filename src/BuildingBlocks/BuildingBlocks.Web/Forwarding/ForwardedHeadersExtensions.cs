using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace BuildingBlocks.Web.Forwarding;

public static class ForwardedHeadersExtensions
{
    /// <summary>
    /// X-Forwarded-For/Proto handling for pods behind the ingress. Without it, RemoteIpAddress
    /// is the ingress/node address — which silently breaks IP rate-limit partitions (all
    /// external callers share one bucket) and the client IP in request logs.
    /// </summary>
    public static IServiceCollection AddMsvcForwardedHeaders(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<MsvcForwardedHeadersOptions>()
            .Bind(configuration.GetSection(MsvcForwardedHeadersOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        var options = configuration.GetSection(MsvcForwardedHeadersOptions.SectionName).Get<MsvcForwardedHeadersOptions>()
            ?? new MsvcForwardedHeadersOptions();

        services.Configure<ForwardedHeadersOptions>(forwarded =>
        {
            forwarded.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            forwarded.ForwardLimit = options.ForwardLimit;

            // Empty trust lists = the middleware skips the known-source check (trust all),
            // exactly like ASPNETCORE_FORWARDEDHEADERS_ENABLED. Non-empty = only those sources.
            forwarded.KnownIPNetworks.Clear();
            forwarded.KnownProxies.Clear();
            foreach (var cidr in options.KnownNetworks)
            {
                forwarded.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(cidr));
            }

            foreach (var proxy in options.KnownProxies)
            {
                forwarded.KnownProxies.Add(IPAddress.Parse(proxy));
            }
        });

        return services;
    }

    /// <summary>No-op when "ForwardedHeaders:Enabled" is false. Must run first in the pipeline.</summary>
    public static WebApplication UseMsvcForwardedHeaders(this WebApplication app)
    {
        if (app.Services.GetRequiredService<IOptions<MsvcForwardedHeadersOptions>>().Value.Enabled)
        {
            app.UseForwardedHeaders();
        }

        return app;
    }
}
