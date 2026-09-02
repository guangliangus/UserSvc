using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Features.BackOffice.SignIn;

/// <summary>Sign in to the back office with a corporate mailbox and a password.</summary>
public sealed record BackOfficePasswordSignInRequest
{
    /// <summary>The address the account's e-mail identity was created from. Matched exactly, after
    /// normalization - there is no fuzzy lookup on a blind index.</summary>
    public string Email { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;
}

/// <summary>
/// Sign in with the corporate one-time password.
/// <para>
/// The client supplies only the employee number and the code. The mailbox, the name and the
/// department come from the HR record, which is why this path needs no address from the caller and
/// applies no domain gate to one.
/// </para>
/// </summary>
public sealed record BackOfficeStaffOtpSignInRequest
{
    /// <summary>The corporate employee number. It is the stable key an account is matched on, so a
    /// mailbox change does not create a second account.</summary>
    public string StaffId { get; init; } = string.Empty;

    /// <summary>The code the operator typed. Never logged and never audited.</summary>
    public string OneTimePassword { get; init; } = string.Empty;
}

/// <summary>
/// The request facts a sign-in records but cannot discover for itself: where it came from and how
/// to correlate it.
/// <para>
/// Passed in from the API layer rather than pulled out of an ambient accessor, for the same reason
/// <see cref="BackOfficeCaller"/> is: the audit rows this slice writes are part of its behaviour,
/// and a unit test has to be able to state the address that ends up on one.
/// </para>
/// </summary>
/// <param name="IpAddress">Remote address, as the audit trail records it.</param>
/// <param name="UserAgent">Client user agent, recorded on the device session.</param>
/// <param name="RequestId">Correlation id, so an audit row joins to the request log.</param>
public sealed record BackOfficeSignInContext(
    string IpAddress = "",
    string UserAgent = "",
    string RequestId = "")
{
    public static BackOfficeSignInContext None { get; } = new();
}

/// <summary>
/// What a completed back-office sign-in answers with.
/// <para>
/// <b>It carries no access token and no refresh token, and that is this service's shape rather
/// than an omission.</b> Credentials come out of the OpenIddict token endpoint and nowhere else
/// (decision 10) - exactly as consumer registration and passkey sign-in issue none either. What
/// this response carries instead is <see cref="SignInTicket"/>, which the client redeems at
/// <c>/connect/token</c> for the token the sign-in decided it should have.
/// </para>
/// <para>
/// <b>Every authority collection is always present and never null.</b> Absence and emptiness are
/// different answers to the shell: an empty list says "nothing is granted" and closes the gates,
/// while a missing field reads as "this backend does not state menus" and opens them. An account
/// that signed in with no authority at all - a PENDING one, or one nobody has added to a tenant -
/// must therefore travel as a set of empty lists rather than as a thinner object.
/// </para>
/// </summary>
public sealed record BackOfficeSignInResponse
{
    public required int UserId { get; init; }

    /// <summary>
    /// True when this sign-in has more than one context to choose between. The ticket then mints a
    /// pre-tenant token, which reaches the two context-selection endpoints and nothing else, and
    /// the authority fields below are all empty because no context has been entered yet.
    /// </summary>
    public required bool ContextRequired { get; init; }

    /// <summary>
    /// The single-window proof of this sign-in, to be presented at the token endpoint. It is a
    /// bearer credential for this account until it expires; treat it like a password.
    /// </summary>
    public required string SignInTicket { get; init; }

    /// <summary>Seconds the ticket remains redeemable, so a client can decide whether to redeem it
    /// or start over rather than discovering the answer from a failed token request.</summary>
    public required int TicketExpiresIn { get; init; }

    /// <summary>
    /// The OAuth scope the ticket will produce - <c>backoffice</c> or <c>backoffice_pre_tenant</c>.
    /// Stated so a client asks the token endpoint for what it is actually going to get; asking for
    /// the other one is refused rather than quietly downgraded.
    /// </summary>
    public required string GrantedScope { get; init; }

    public required BackOfficeUserResponse User { get; init; }

    /// <summary>INTERNAL | EXTERNAL. It decides whether the corporate domain gate applies to this
    /// account's password door.</summary>
    public required string Origin { get; init; }

    /// <summary>Whether this account holds whole-dimension access anywhere. The platform
    /// super-administrator flag counts.</summary>
    public required bool IsGlobal { get; init; }

    /// <summary>Where the session will be acting, or null when nothing has been chosen yet.</summary>
    public ActiveTenantResponse? ActiveTenant { get; init; }

    public bool IsTenantAdmin { get; init; }

    public IReadOnlyList<string> Roles { get; init; } = [];

    public IReadOnlyList<string> Permissions { get; init; } = [];

    public IReadOnlyList<string> Menus { get; init; } = [];

    public IReadOnlyDictionary<string, ScopeClaim> Scopes { get; init; } =
        TenantContextResult.EmptyScopeEnvelope();

    /// <summary>
    /// The contexts this account may enter. Populated whenever there is a choice to render, and
    /// deliberately empty for the platform super administrator, whose only context is the platform
    /// one - the switcher draws a badge for them rather than a menu with one item in it.
    /// </summary>
    public IReadOnlyList<TenantSummaryResponse> Tenants { get; init; } = [];
}

/// <summary>
/// What a redeemed ticket, or a context exchange, entitles the token endpoint to mint. It is the
/// application layer's whole answer to "what should this token say"; assembling the claims is the
/// API layer's job.
/// </summary>
/// <param name="UserId">Subject of the token. A back-office account id.</param>
/// <param name="ActorName">Display name, for the <c>name</c> claim and the audit trail.</param>
/// <param name="TokenVersion">Value of the <c>ver</c> claim; the authority snapshot's cache key.</param>
/// <param name="Act">The context, or null for a pre-tenant token and for a no-authority session.</param>
/// <param name="IsPreTenant">
/// Whether this is the unfinished half of a sign-in. It decides the scope, the lifetime and
/// whether a refresh token is issued at all - a token that has not chosen a context must not leave
/// a long-lived credential behind.
/// </param>
public sealed record BackOfficeTokenGrant(
    int UserId,
    string ActorName,
    int TokenVersion,
    ActClaim? Act,
    bool IsPreTenant);
