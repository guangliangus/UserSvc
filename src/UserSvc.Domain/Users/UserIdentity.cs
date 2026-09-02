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

    /// <summary>
    /// Which application inside a provider issued the identifier, or empty when the provider has
    /// no such concept. WeChat is the reason it exists: the mini program and the website are two
    /// WeChat applications with two openid spaces, so <c>WECHAT_MINI</c> rows carry
    /// <c>miniprogram</c> and web OAuth rows carry the empty string. Firebase reuses it for the
    /// sign-in provider (<c>google.com</c>, <c>apple.com</c>, <c>facebook.com</c>).
    /// </summary>
    public string Provider { get; set; } = string.Empty;

    /// <summary>
    /// The provider's own durable subject for this person, stored in the clear because it is not a
    /// credential and because it carries a unique index the identifier's blind index cannot.
    /// <para>
    /// It answers a question <see cref="IdentifierHash"/> cannot. For WeChat it is the union id,
    /// the same across every app of one Open Platform account - the only way to recognise that a
    /// mini-program openid and a web openid are one human. For Firebase it is the third-party
    /// account's sub, which outlives the Firebase uid: delete and re-create a Firebase user and the
    /// uid changes while this does not.
    /// </para>
    /// </summary>
    public string ProviderUid { get; set; } = string.Empty;

    /// <summary>Provider-supplied decoration in <c>jsonb</c>. Never a lookup key.</summary>
    public string ProviderDetails { get; set; } = "{}";

    public string Status { get; set; } = UserStatuses.Active;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public string UpdatedBy { get; set; } = string.Empty;
}
