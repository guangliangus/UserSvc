namespace UserSvc.Domain.Users;

/// <summary>
/// One way to sign in (phone / email / third party). The identifier itself is stored as a blind
/// index plus a ciphertext column; the plaintext never reaches the database (decision 13).
/// </summary>
public sealed class UserIdentity
{
    public int Id { get; set; }
    public int UserId { get; set; }

    /// <summary>See <see cref="IdentityTypes"/>.</summary>
    public string IdentityType { get; set; } = string.Empty;

    /// <summary>Blind index: HMAC-SHA256(identifier, pepper). The unique index lives on this column.</summary>
    public string IdentifierHash { get; set; } = string.Empty;
    public string IdentifierCiphertext { get; set; } = string.Empty;
    public string IdentifierKeyVersion { get; set; } = string.Empty;

    public string Status { get; set; } = UserStatuses.Active;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public string UpdatedBy { get; set; } = string.Empty;
}
