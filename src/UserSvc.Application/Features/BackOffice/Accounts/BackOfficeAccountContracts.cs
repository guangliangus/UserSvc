namespace UserSvc.Application.Features.BackOffice.Accounts;

/// <summary>
/// Back-office sign-up. The caller has already proved control of <see cref="Email"/> through the
/// verification flow and holds the ticket that proves it; this request spends that ticket.
/// <para>
/// There is no identity-type field, unlike consumer registration: the back office registers a
/// corporate mailbox and nothing else.
/// </para>
/// </summary>
public sealed record BackOfficeRegisterRequest
{
    public string Email { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    /// <summary>The single-use ticket minted when the emailed code was verified. Spent inside the
    /// same transaction as the account write, so it dies with the account it created.</summary>
    public string VerificationTicket { get; init; } = string.Empty;

    public string? FirstName { get; init; }

    public string? LastName { get; init; }

    public string? Avatar { get; init; }
}

/// <summary>
/// The account that now has a password. Not a sign-in response - registering hands out no
/// credential, and the client authenticates next.
/// </summary>
public sealed record BackOfficeRegisterResponse
{
    public required int Id { get; init; }

    /// <summary>
    /// Usually <c>PENDING</c>: proving control of a corporate mailbox creates an account, it does
    /// not grant it anything. An operator activates it, and until then the account can sign in and
    /// see nothing. It is <c>ACTIVE</c> only when the row already existed and was already active -
    /// staff who signed in through the corporate one-time-password path first and are now setting
    /// a local password.
    /// </summary>
    public required string Status { get; init; }
}

/// <summary>
/// Self-service back-office password reset. The mailbox was proved through the back-office reset
/// verification flow; this request spends that ticket and replaces the password.
/// </summary>
public sealed record BackOfficePasswordResetRequest
{
    public string Email { get; init; } = string.Empty;

    public string NewPassword { get; init; } = string.Empty;

    public string VerificationTicket { get; init; } = string.Empty;
}

/// <summary>
/// The request facts the self-service reset needs and cannot discover for itself.
/// <para>
/// Passed in from the API layer rather than read from an ambient accessor, for the reason every
/// other context record in this service gives: the budget it charges and the audit row it writes
/// are part of this use case's behaviour, and a unit test has to be able to state the address that
/// ends up on one.
/// </para>
/// </summary>
/// <param name="IpAddress">The peer address, as the socket reports it. Empty when there is none to
/// attribute to - the use case then charges one shared bucket rather than handing a limiter a blank
/// subject.</param>
/// <param name="RequestId">Correlation id, so the audit row of a credential change nobody signed
/// in for joins to the request log.</param>
public sealed record BackOfficeResetContext(string IpAddress = "", string RequestId = "")
{
    /// <summary>No address and no correlation id - the shape a caller outside HTTP passes.</summary>
    public static BackOfficeResetContext None { get; } = new();
}

/// <summary>The back-office directory query, as bound from the query string.</summary>
public sealed record BackOfficeUserListRequest
{
    /// <summary>1-based. Anything below 1 is read as the first page rather than refused - a pager
    /// that sends 0 is a client bug the operator should not have to see.</summary>
    public int Page { get; init; } = 1;

    public int PageSize { get; init; } = 20;

    /// <summary>Exact account status, or null for every status.</summary>
    public string? Status { get; init; }

    /// <summary>
    /// A name fragment, an employee number, or a complete email address. An address matches only in
    /// full: addresses are stored as a deterministic hash, so there is no prefix to search - which
    /// is also why a name search can never stumble onto one.
    /// </summary>
    public string? Search { get; init; }
}

/// <summary>One page of the back-office directory.</summary>
public sealed record BackOfficeUserListResponse
{
    public required IReadOnlyList<BackOfficeUserResponse> Items { get; init; }

    /// <summary>How many accounts the filter matched in total, not how many are on this page.</summary>
    public required int Total { get; init; }

    public required int Page { get; init; }

    public required int PageSize { get; init; }

    public required int TotalPages { get; init; }
}

/// <summary>
/// One back-office account as the directory shows it.
/// <para>
/// <b>It deliberately carries no roles, memberships or administrator flag yet.</b> Those come from
/// the tenant tables, which this slice does not own, and stating them as empty would be a specific
/// claim - "this account holds nothing" - rather than the truth, which is "this deployment does not
/// yet answer that question". A field that is absent falls back; a field that says <c>[]</c> closes
/// a gate.
/// </para>
/// </summary>
public sealed record BackOfficeUserResponse
{
    public required int Id { get; init; }

    public string? FirstName { get; init; }

    public string? LastName { get; init; }

    /// <summary>The composed display name, not the raw stored handle - see
    /// <see cref="BackOfficeNames.DisplayName"/>.</summary>
    public string? Nickname { get; init; }

    public string? Avatar { get; init; }

    /// <summary>
    /// The account's primary address in plaintext, or empty when it has none or the ciphertext
    /// could not be read. Decrypted on purpose: whoever provisions an account has to be able to see
    /// the address the generated password was mailed to, and that is the audience this endpoint is
    /// gated to.
    /// </summary>
    public string Email { get; init; } = string.Empty;

    public required string Status { get; init; }

    public string? StaffCode { get; init; }

    public string? DeptName { get; init; }

    /// <summary><c>INTERNAL</c> or <c>EXTERNAL</c>.</summary>
    public string? Origin { get; init; }

    /// <summary>
    /// Whether this account owns the platform. <b>Populated only for a caller whose own visibility
    /// is unrestricted</b>, which is to say another platform super administrator; for a tenant
    /// administrator it is always false. Who the platform owners are is not a tenant
    /// administrator's business, and the flag is caller-gated by construction rather than by a
    /// check someone has to remember.
    /// </summary>
    public bool IsSuperAdmin { get; init; }

    public DateTimeOffset? LastLoginAt { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>
/// A people-picker entry. Both names are composed, because the picker is a search box and an
/// operator types what they see on screen.
/// </summary>
public sealed record BackOfficeUserOptionResponse
{
    public required int Id { get; init; }

    /// <summary>The composed display name.</summary>
    public required string Nickname { get; init; }

    /// <summary>Given and family name joined in the order this name's script uses - never
    /// "first space last", which mangles a CJK name.</summary>
    public required string FullName { get; init; }
}

/// <summary>
/// Grants or revokes the platform super-administrator identity.
/// <para>
/// <see cref="Enabled"/> is nullable so that "the client did not say" is distinguishable from
/// "the client said false". The validator refuses null: on the one lever that hands out or takes
/// away ownership of the whole platform, a missing field must not be read as an instruction.
/// </para>
/// </summary>
public sealed record SetSuperAdminRequest
{
    public bool? Enabled { get; init; }
}
