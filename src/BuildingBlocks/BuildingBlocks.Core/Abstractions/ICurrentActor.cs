namespace BuildingBlocks.Core.Abstractions;

/// <summary>
/// Identifies who is performing the current unit of work, used for audit columns.
/// HTTP requests resolve it from the JWT (sub/client_id), message consumers from the
/// message header; background work falls back to <see cref="SystemActor.Name"/>.
/// </summary>
public interface ICurrentActor
{
    string Actor { get; }
}

public static class SystemActor
{
    public const string Name = "system";
}

/// <summary>Fallback actor for hosts without an ambient caller (workers, dispatchers, jobs).</summary>
public sealed class SystemCurrentActor : ICurrentActor
{
    public string Actor => SystemActor.Name;
}
