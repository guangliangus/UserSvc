using System.ComponentModel.DataAnnotations;

namespace BuildingBlocks.Observability;

public sealed class ObservabilityOptions
{
    public const string SectionName = "Observability";

    /// <summary>
    /// OTLP endpoint for trace export (e.g. http://jaeger:4317). Empty disables the exporter
    /// unless OTEL_EXPORTER_OTLP_ENDPOINT is set. Metrics are NOT pushed over OTLP —
    /// Prometheus scrapes /metrics; the two signals deliberately use separate paths.
    /// </summary>
    public string? OtlpEndpoint { get; set; }

    /// <summary>"json" (default, for cluster log collectors) or "text" (local dev readability).</summary>
    public string ConsoleFormat { get; set; } = "json";

    /// <summary>
    /// Head-sampling ratio for traces (0..1). Applied parent-based, so a sampled upstream
    /// span keeps its children sampled across services. 1.0 records everything — fine locally,
    /// expensive in production; tail sampling belongs to the collector, not the app.
    /// </summary>
    [Range(0.0, 1.0)]
    public double TraceSampleRatio { get; set; } = 1.0;

    /// <summary>
    /// Top-level log property names whose values are replaced with "***".
    /// Default-empty because the config binder appends to (rather than replaces) non-empty
    /// default arrays; read via <see cref="EffectiveMaskedProperties"/>.
    /// </summary>
    public string[] MaskedProperties { get; set; } = [];

    public string[] EffectiveMaskedProperties => MaskedProperties.Length > 0 ? MaskedProperties : DefaultMasked;

    private static readonly string[] DefaultMasked =
        ["password", "secret", "token", "authorization", "clientSecret"];
}
