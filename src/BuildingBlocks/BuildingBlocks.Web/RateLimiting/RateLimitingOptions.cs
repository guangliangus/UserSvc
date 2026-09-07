namespace BuildingBlocks.Web.RateLimiting;

public enum RateLimitPolicyType
{
    FixedWindow,
    SlidingWindow,
    TokenBucket,
    Concurrency,
}

public enum RateLimitPartitionStrategy
{
    /// <summary>One shared bucket.</summary>
    None,

    /// <summary>Per remote IP.</summary>
    Ip,

    /// <summary>Per authenticated caller (azp/client_id/sub claim), falling back to IP.</summary>
    Caller,
}

public sealed class RateLimitPolicyOptions
{
    public RateLimitPolicyType Type { get; set; } = RateLimitPolicyType.FixedWindow;
    public RateLimitPartitionStrategy PartitionBy { get; set; } = RateLimitPartitionStrategy.Caller;

    /// <summary>Window/concurrency permit count, or bucket size for TokenBucket.</summary>
    public int PermitLimit { get; set; } = 100;

    public int WindowSeconds { get; set; } = 60;

    /// <summary>SlidingWindow only.</summary>
    public int SegmentsPerWindow { get; set; } = 8;

    /// <summary>TokenBucket only.</summary>
    public int TokensPerPeriod { get; set; } = 10;

    /// <summary>TokenBucket only.</summary>
    public int ReplenishmentPeriodSeconds { get; set; } = 1;

    public int QueueLimit { get; set; }
}

/// <summary>
/// Bound from "RateLimiting". NOTE: in-process limits are per pod — the effective global
/// budget is (configured value × replica count) and grows when HPA scales out. True global
/// rate limiting belongs to the gateway, not this template.
/// </summary>
public sealed class RateLimitingOptions
{
    public const string SectionName = "RateLimiting";

    public bool Enabled { get; set; } = true;

    /// <summary>Optional policy name applied to every endpoint (before named per-route policies).</summary>
    public string? GlobalPolicy { get; set; }

    public Dictionary<string, RateLimitPolicyOptions> Policies { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
