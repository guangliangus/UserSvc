using System.ComponentModel.DataAnnotations;

namespace UserSvc.Application.Security;

/// <summary>
/// Key material for identifier protection. <b>In production this must come from Key Vault or
/// ExternalSecrets, never from appsettings</b> (decision 13). Configuration holds only a reference.
/// </summary>
public sealed class IdentifierProtectionOptions
{
    public const string SectionName = "IdentifierProtection";

    /// <summary>HMAC pepper for the blind index, hex encoded.</summary>
    [Required(AllowEmptyStrings = false)]
    public string Pepper { get; init; } = string.Empty;

    /// <summary>Current data encryption key (DEK): 32 bytes, base64 encoded.</summary>
    [Required(AllowEmptyStrings = false)]
    public string DataKey { get; init; } = string.Empty;

    /// <summary>Current key version. Written to the <c>*_key_version</c> columns so the rotation
    /// job can find the rows that still need re-encrypting.</summary>
    [Required(AllowEmptyStrings = false)]
    public string KeyVersion { get; init; } = "v1";
}
