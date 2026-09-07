using System.ComponentModel.DataAnnotations;

namespace BuildingBlocks.Web.Auth;

/// <summary>Bound from "Auth".</summary>
public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    /// <summary>OIDC authority, e.g. https://idp.example.com/realms/msvc.</summary>
    [Required(AllowEmptyStrings = false)]
    public string Authority { get; set; } = string.Empty;

    [Required(AllowEmptyStrings = false)]
    public string Audience { get; set; } = string.Empty;

    /// <summary>Disable only for local/in-cluster plain-HTTP IdPs.</summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Extra accepted issuers. Needed locally where the token is fetched via localhost but
    /// validated against the in-network authority URL (issuer strings differ). Empty = the
    /// issuer from authority discovery only.
    /// </summary>
    public string[] ValidIssuers { get; set; } = [];
}
