namespace BuildingBlocks.Core.Abstractions;

/// <summary>Testable time source. All persisted timestamps are UTC (timestamptz).</summary>
public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
