namespace UserSvc.Domain.BackOffice;

/// <summary>
/// A back-office (B-end) account: the person who signs in to the administration console.
/// <para>
/// <b>It is physically separate from the consumer <see cref="Users.User"/> table and has its own id
/// sequence</b>, which is the whole reason this type exists rather than a flag on the consumer
/// account. The same mailbox can be a customer and an operator at once, and those are two accounts
/// with two passwords, two statuses and two lifecycles - collapsing them would mean disabling an
/// employee also disables their personal booking account. The two planes live in different schemas
/// (<c>iam</c> and <c>identity</c>) with no foreign key between them, so nothing can accidentally
/// join them back together.
/// </para>
/// <para>
/// <b>Deliberately flat</b> (the same call as <see cref="Users.User"/>): these are CRUD fields, and
/// the one rule worth protecting - that the platform never runs out of super administrators - is
/// not enforceable in memory at all. It lives in a SQL predicate, because two concurrent revokes
/// each holding a correct in-memory object would both pass and leave nobody. See
/// <c>IBackendUserRepository.RevokeSuperAdminIfAnotherActiveExistsAsync</c>.
/// </para>
/// <para>
/// Most string columns are nullable, and the properties mirror that. The live table carries NULLs
/// in them today, so a non-nullable CLR property would be a claim the data does not support: EF
/// would hand back a null through a <c>string</c> reference and the first interpolation would
/// print an empty string while the next null check said otherwise. The team convention prefers
/// NOT NULL DEFAULT '' and the next greenfield table should use it; existing rows are the
/// constraint here.
/// </para>
/// </summary>
public sealed class BackendUser
{
    public int Id { get; set; }

    /// <summary>
    /// Argon2id PHC string, or null for an account provisioned without one - staff who only ever
    /// signed in through the corporate OTP path have no local password until they set one. Null is
    /// therefore meaningful: it is "this account cannot use the password door", not "unknown".
    /// </summary>
    public string? PasswordHash { get; set; }

    public string? FirstName { get; set; }

    public string? LastName { get; set; }

    /// <summary>Display handle. Never the composed full name - see <c>BackOfficeNames.DisplayName</c>,
    /// which is what every screen actually shows.</summary>
    public string? Nickname { get; set; }

    public string? Avatar { get; set; }

    /// <summary>The corporate employee number. Stable across renames and mailbox changes, which is
    /// why the OTP login path matches on it first.</summary>
    public string? StaffCode { get; set; }

    public string? DeptNo { get; set; }

    public string? DeptName { get; set; }

    /// <summary>See <see cref="BackendUserStatuses"/>. PENDING may sign in - it simply holds no
    /// authority yet.</summary>
    public string Status { get; set; } = BackendUserStatuses.Pending;

    /// <summary>
    /// INTERNAL (group staff) or EXTERNAL (a B2B partner). The only thing it decides is whether the
    /// corporate email-domain gate applies at sign-in: an external supplier authenticates with
    /// whatever mailbox they have. See <see cref="BackendUserOrigins"/>.
    /// </summary>
    public string Origin { get; set; } = BackendUserOrigins.Internal;

    /// <summary>
    /// Baseline for the token's version claim. Bumping it invalidates every access token this
    /// account is currently holding, without waiting for them to expire - which is what makes a
    /// password reset or a status change take effect now rather than in ten minutes.
    /// </summary>
    public int TokenVersion { get; set; }

    /// <summary>
    /// The platform super administrator flag: <b>an identity, not a breadth</b>. It hardcodes all
    /// permissions, all menus and both global data scopes wherever the holder acts, and it is
    /// exclusive with tenant memberships.
    /// <para>
    /// <b>Written only by the dedicated repository methods.</b> Nothing that maps a request onto
    /// this entity may set it: a generic update path that happened to carry a stale <c>true</c>
    /// would silently mint an owner of the whole platform, and revocation must go through the
    /// guarded statement that refuses to remove the last active one.
    /// </para>
    /// </summary>
    public bool IsSuperAdmin { get; set; }

    public DateTimeOffset? LastLoginAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public string? CreatedBy { get; set; }

    public string? UpdatedBy { get; set; }

    /// <summary>
    /// The account's login identities. Present so registration can insert the account and its first
    /// identity in one round trip, with EF filling <c>user_id</c> from the key it just generated.
    /// </summary>
    public List<BackendIdentity> Identities { get; } = [];

    public bool IsActive() => Status == BackendUserStatuses.Active;

    /// <summary>Whether the account can sign in with a password at all. An account provisioned
    /// through the corporate OTP path has no local password until it registers one.</summary>
    public bool HasPassword() => !string.IsNullOrEmpty(PasswordHash);
}
