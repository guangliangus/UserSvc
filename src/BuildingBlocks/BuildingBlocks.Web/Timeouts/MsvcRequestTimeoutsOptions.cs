using System.ComponentModel.DataAnnotations;

namespace BuildingBlocks.Web.Timeouts;

/// <summary>
/// Bound from "RequestTimeouts". Inbound request budget — separate from the downstream
/// HttpClient timeouts configured under ServiceClients:{name}:Resilience.
/// </summary>
public sealed class MsvcRequestTimeoutsOptions
{
    public const string SectionName = "RequestTimeouts";

    public bool Enabled { get; set; } = true;

    /// <summary>Default per-request budget, applied to every endpoint without an explicit policy.</summary>
    [Range(1, 3600)]
    public int DefaultTimeoutSeconds { get; set; } = 30;

    /// <summary>Named policies (seconds per name) for endpoints marked [RequestTimeout("name")].</summary>
    public Dictionary<string, int> Policies { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The errorCode extension member on the 504 ProblemDetails. Configurable because the error
    /// code is a client contract and services differ in casing convention; the default follows
    /// the template's snake_case codes.
    /// </summary>
    [Required(AllowEmptyStrings = false)]
    public string ErrorCode { get; set; } = "request_timeout";
}
