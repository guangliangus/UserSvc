namespace UserSvc.Domain.Users;

/// <summary>
/// A consumer account. <b>Deliberately kept flat</b> (decision 04): it has no invariants worth
/// protecting in the domain layer — profile fields are CRUD, and the rules that do exist are
/// orchestrated by the application layer. The concepts that earn a rich model are the ones where
/// breaking an invariant is a security incident, such as <see cref="Auth.UserSession"/>.
/// </summary>
public sealed class User
{
    public int Id { get; set; }

    public string Status { get; set; } = UserStatuses.Pending;

    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Nickname { get; set; } = string.Empty;
    public string Avatar { get; set; } = string.Empty;
    public string ResidenceCountryCode { get; set; } = string.Empty;

    /// <summary>Password hash algorithm (decision 13: legacy rows carry BCRYPT and are upgraded
    /// to ARGON2ID on the next successful sign-in).</summary>
    public string PasswordAlgo { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>Blind index: HMAC-SHA256(birth date, pepper). Enables exact match without
    /// storing the plaintext.</summary>
    public string BirthDateHash { get; set; } = string.Empty;
    /// <summary>Envelope-encrypted birth date (AES-256-GCM).</summary>
    public string BirthDateCiphertext { get; set; } = string.Empty;
    /// <summary>DEK version used to encrypt, so the rotation job can find rows to re-encrypt.</summary>
    public string BirthDateKeyVersion { get; set; } = string.Empty;

    public DateTimeOffset? LastLoginAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public string UpdatedBy { get; set; } = string.Empty;

    public List<UserIdentity> Identities { get; set; } = [];

    public bool IsActive() => Status == UserStatuses.Active;
}
