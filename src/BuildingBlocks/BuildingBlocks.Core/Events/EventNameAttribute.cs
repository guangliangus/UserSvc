using System.Collections.Concurrent;
using System.Text;

namespace BuildingBlocks.Core.Events;

/// <summary>
/// Stable wire name of an integration event, used as the routing key. Prefer setting it
/// explicitly — renaming a class must never silently change the routing key.
/// </summary>
[AttributeUsage(AttributeTargets.Class, Inherited = false)]
public sealed class EventNameAttribute(string name) : Attribute
{
    public string Name { get; } = name;
}

public static class EventName
{
    private static readonly ConcurrentDictionary<Type, string> Cache = new();

    /// <summary>[EventName] if present; otherwise type name minus an "Event" suffix in dot.case ("OrderCreatedEvent" → "order.created").</summary>
    public static string For(Type eventType) => Cache.GetOrAdd(eventType, static t =>
    {
        var attr = (EventNameAttribute?)Attribute.GetCustomAttribute(t, typeof(EventNameAttribute));
        if (attr is not null)
        {
            return attr.Name;
        }

        var name = t.Name;
        if (name.EndsWith("Event", StringComparison.Ordinal) && name.Length > "Event".Length)
        {
            name = name[..^"Event".Length];
        }

        var sb = new StringBuilder(name.Length + 4);
        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c) && i > 0)
            {
                sb.Append('.');
            }

            sb.Append(char.ToLowerInvariant(c));
        }

        return sb.ToString();
    });

    public static string For<TEvent>() where TEvent : IntegrationEvent => For(typeof(TEvent));
}
