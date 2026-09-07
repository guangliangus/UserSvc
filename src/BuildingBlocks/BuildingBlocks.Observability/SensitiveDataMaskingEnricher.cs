using Serilog.Core;
using Serilog.Events;

namespace BuildingBlocks.Observability;

/// <summary>
/// Replaces the values of configured top-level log properties with "***".
/// A guardrail, not a substitute for keeping secrets out of log statements.
/// </summary>
public sealed class SensitiveDataMaskingEnricher(IEnumerable<string> maskedProperties) : ILogEventEnricher
{
    private static readonly LogEventPropertyValue Mask = new ScalarValue("***");
    private readonly HashSet<string> _masked = new(maskedProperties, StringComparer.OrdinalIgnoreCase);

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        List<string>? hits = null;
        foreach (var name in logEvent.Properties.Keys)
        {
            if (_masked.Contains(name))
            {
                (hits ??= []).Add(name);
            }
        }

        if (hits is null)
        {
            return;
        }

        foreach (var name in hits)
        {
            logEvent.AddOrUpdateProperty(new LogEventProperty(name, Mask));
        }
    }
}
