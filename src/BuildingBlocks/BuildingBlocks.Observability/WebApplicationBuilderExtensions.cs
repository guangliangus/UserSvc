using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using Serilog.Events;
using Serilog.Formatting.Compact;

namespace BuildingBlocks.Observability;

public static class WebApplicationBuilderExtensions
{
    private const string TextOutputTemplate =
        "[{Timestamp:HH:mm:ss} {Level:u3}] [{TraceId}] {Message:lj}{NewLine}{Exception}";

    /// <summary>
    /// Wires Serilog (JSON to stdout, trace-correlated, masked) and OpenTelemetry.
    /// Signal routing is fixed: traces → OTLP push, metrics → /metrics Prometheus scrape,
    /// logs → stdout for the cluster log collector. The "Serilog" configuration section can
    /// override levels; "Observability" configures the rest.
    /// </summary>
    public static WebApplicationBuilder AddMsvcObservability(
        this WebApplicationBuilder builder,
        string serviceName,
        Action<ObservabilitySources>? configureSources = null)
    {
        builder.Services.AddOptions<ObservabilityOptions>()
            .Bind(builder.Configuration.GetSection(ObservabilityOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        var options = builder.Configuration.GetSection(ObservabilityOptions.SectionName).Get<ObservabilityOptions>()
            ?? new ObservabilityOptions();
        var sources = new ObservabilitySources();
        configureSources?.Invoke(sources);

        builder.Host.UseSerilog((context, loggerConfiguration) =>
        {
            loggerConfiguration
                .MinimumLevel.Information()
                .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning)
                .MinimumLevel.Override("Quartz", LogEventLevel.Warning)
                .Enrich.FromLogContext()
                .Enrich.WithMachineName()
                .Enrich.WithProperty("service", serviceName)
                .Enrich.With(new SensitiveDataMaskingEnricher(options.EffectiveMaskedProperties));

            if (string.Equals(options.ConsoleFormat, "text", StringComparison.OrdinalIgnoreCase))
            {
                // Same correlation as the JSON sink's @tr: the bare 32-hex trace id, which is also
                // the traceId the error contract publishes. Serilog fills {TraceId} from
                // Activity.Current, so it renders empty outside a request (startup lines).
                loggerConfiguration.WriteTo.Console(outputTemplate: TextOutputTemplate);
            }
            else
            {
                loggerConfiguration.WriteTo.Console(new CompactJsonFormatter());
            }

            // Applied last so appsettings ("Serilog" section) can override levels per environment.
            loggerConfiguration.ReadFrom.Configuration(context.Configuration);
        });

        var otel = builder.Services.AddOpenTelemetry()
            .ConfigureResource(r => r.AddService(
                serviceName,
                serviceVersion: typeof(WebApplicationBuilderExtensions).Assembly.GetName().Version?.ToString(),
                serviceInstanceId: Environment.MachineName));

        otel.WithTracing(tracing =>
        {
            tracing
                // Parent-based: honor the upstream decision, ratio-sample new roots.
                .SetSampler(new ParentBasedSampler(new TraceIdRatioBasedSampler(options.TraceSampleRatio)))
                .AddAspNetCoreInstrumentation(o =>
                    o.Filter = ctx => !IsInfrastructurePath(ctx.Request.Path.Value))
                .AddHttpClientInstrumentation()
                .AddNpgsql()
                .AddEntityFrameworkCoreInstrumentation();

            foreach (var source in sources.ActivitySources)
            {
                tracing.AddSource(source);
            }

            var otlpEndpoint = options.OtlpEndpoint
                ?? builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];
            if (!string.IsNullOrWhiteSpace(otlpEndpoint))
            {
                tracing.AddOtlpExporter(o => o.Endpoint = new Uri(otlpEndpoint));
            }
        });

        otel.WithMetrics(metrics =>
        {
            metrics
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddRuntimeInstrumentation();

            foreach (var meter in sources.Meters)
            {
                metrics.AddMeter(meter);
            }

            metrics.AddPrometheusExporter();
        });

        return builder;
    }

    internal static bool IsInfrastructurePath(string? path) =>
        path is not null
        && (path.StartsWith("/health", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/metrics", StringComparison.OrdinalIgnoreCase));
}
