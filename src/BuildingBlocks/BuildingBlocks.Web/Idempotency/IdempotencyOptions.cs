using System.ComponentModel.DataAnnotations;

namespace BuildingBlocks.Web.Idempotency;

/// <summary>Bound from "Idempotency".</summary>
public sealed class IdempotencyOptions
{
    public const string SectionName = "Idempotency";

    public bool Enabled { get; set; } = true;

    [Required(AllowEmptyStrings = false)]
    public string HeaderName { get; set; } = "Idempotency-Key";

    /// <summary>
    /// How long a claim blocks concurrent duplicates (409) while the first request executes.
    /// Also the crash-recovery bound: if the owner dies mid-request, the key frees itself
    /// after this TTL. Keep it above the request timeout.
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:01", "00:30:00")]
    public TimeSpan InFlightTtl { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>How long successful response snapshots are kept and replayed.</summary>
    [Range(typeof(TimeSpan), "00:01:00", "30.00:00:00")]
    public TimeSpan Retention { get; set; } = TimeSpan.FromHours(24);

    /// <summary>Responses larger than this are not stored (the request still succeeds; a retry re-executes).</summary>
    [Range(1024, 8 * 1024 * 1024)]
    public int MaxBodyBytes { get; set; } = 256 * 1024;

    /// <summary>
    /// HTTP methods guarded by the middleware. Default-empty on purpose (the config binder
    /// appends to non-empty default arrays); read via <see cref="EffectiveMethods"/>.
    /// </summary>
    public string[] Methods { get; set; } = [];

    /// <summary>Configured methods, or POST + PATCH when none are configured.</summary>
    public string[] EffectiveMethods => Methods.Length > 0 ? Methods : DefaultMethods;

    private static readonly string[] DefaultMethods = ["POST", "PATCH"];
}
