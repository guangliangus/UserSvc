namespace BuildingBlocks.Observability;

/// <summary>Extra telemetry sources a host wants collected (e.g. the messaging ActivitySource, custom business meters).</summary>
public sealed class ObservabilitySources
{
    public List<string> ActivitySources { get; } = [];
    public List<string> Meters { get; } = [];
}
