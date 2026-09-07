using System.ComponentModel.DataAnnotations;

namespace BuildingBlocks.Web.Forwarding;

/// <summary>Bound from "ForwardedHeaders".</summary>
public sealed class MsvcForwardedHeadersOptions
{
    public const string SectionName = "ForwardedHeaders";

    /// <summary>Off by default: local dev is called directly. Turn it on behind the K8s ingress (the chart does).</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// CIDRs trusted to supply X-Forwarded-For/Proto (e.g. the pod network). EMPTY (default)
    /// trusts every source — matching ASPNETCORE_FORWARDEDHEADERS_ENABLED semantics. That is
    /// convenient behind a locked-down ingress, but any in-cluster caller can then spoof its
    /// client IP; set real CIDRs (or add a NetworkPolicy) where that matters.
    /// </summary>
    public string[] KnownNetworks { get; set; } = [];

    /// <summary>Individual trusted proxy IPs (rarely needed in K8s; prefer KnownNetworks).</summary>
    public string[] KnownProxies { get; set; } = [];

    /// <summary>How many proxy hops to unwind; 1 = only the closest proxy (the ingress).</summary>
    [Range(1, 10)]
    public int ForwardLimit { get; set; } = 1;
}
