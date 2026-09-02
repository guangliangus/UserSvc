namespace UserSvc.Domain.BackOffice;

/// <summary>
/// One way to sign in to the back office: a corporate mailbox, a phone number, or the employee
/// number the corporate OTP service authenticates.
/// <para>
/// <b>Uniqueness is scoped to this table alone.</b> The same address may exist here and in
/// <c>identity.user_identities</c> at the same time, describing two unrelated accounts - one
/// person's operator login and their own customer login. That is not a duplicate to be cleaned
/// up; it is the point of keeping the two planes apart.
/// </para>
/// <para>
/// The identifier is stored three ways, and each column answers a different question the others
/// cannot: <see cref="IdentifierHash"/> is a blind index for exact lookups, matching the consumer
/// plane's scheme; <see cref="IdentifierCiphertext"/> is how the value is read back; and
/// <see cref="IdentifierMasked"/> is what a screen shows when the ciphertext cannot be decrypted -
/// after a key rotation, for instance - so a directory degrades to a partial address rather than
/// to a blank.
/// </para>
/// </summary>
public sealed class BackendIdentity
{
    public int Id { get; set; }

    /// <summary>Owning <see cref="BackendUser"/>. Column <c>user_id</c>, not
    /// <c>backend_user_id</c>: the table already says which plane it belongs to.</summary>
    public int UserId { get; set; }

    /// <summary>See <see cref="BackendIdentityTypes"/>. Lowercase for <c>email</c> and
    /// <c>phone</c>, uppercase for <c>OTP</c> - the live CHECK constraint spells them that way and
    /// the partial unique indexes match on the literal.</summary>
    public string IdentityType { get; set; } = string.Empty;

    /// <summary>Which upstream vouched for this identity, empty for one this service owns.</summary>
    public string Provider { get; set; } = string.Empty;

    /// <summary>The upstream's own id for the subject, when there is one.</summary>
    public string? ProviderUid { get; set; }

    /// <summary>Blind index: HMAC of the normalized identifier. The partial unique indexes live on
    /// this column, so every writer must normalize identically or "one account per address" quietly
    /// stops holding.</summary>
    public string IdentifierHash { get; set; } = string.Empty;

    public string IdentifierCiphertext { get; set; } = string.Empty;

    /// <summary>The human-readable fallback: enough of the address to recognize, not enough to
    /// deliver to.</summary>
    public string IdentifierMasked { get; set; } = string.Empty;

    /// <summary>DEK version the ciphertext was written with, so a rotation job can find the rows it
    /// still has to re-encrypt.</summary>
    public string KeyVersion { get; set; } = string.Empty;

    /// <summary>Free-form upstream attributes, kept as jsonb. Null when the upstream sent none.</summary>
    public string? ProviderDetails { get; set; }

    /// <summary>ACTIVE or not. Only ACTIVE rows are unique and only ACTIVE rows can be signed in
    /// with, which is what makes an identity revocable without deleting the row.</summary>
    public string Status { get; set; } = BackendIdentityStatuses.Active;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public string? CreatedBy { get; set; }

    public string? UpdatedBy { get; set; }
}
