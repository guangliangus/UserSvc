using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.Auth.TokenValidation;

/// <summary>
/// The facts only the API layer can read off a validated token, handed to
/// <see cref="TokenValidationAppService"/> so the application layer keeps knowing nothing about
/// JWTs.
/// <para>
/// It is deliberately small. Everything else the endpoint answers with is either resolved by the
/// request pipeline already (the caller's identity and authority) or read from the session row —
/// duplicating any of it here would give the endpoint a second source of truth for something the
/// permission gates read from the first.
/// </para>
/// </summary>
public sealed record ValidatedTokenFacts
{
    /// <summary>The <c>sid</c> claim. Empty for a token minted for something other than a device
    /// session, which is not an error: there is then simply no session to check.</summary>
    public string SessionId { get; init; } = string.Empty;

    /// <summary>
    /// Whether this is a back-office credential, decided by the scopes it carries rather than by
    /// the shape of its subject. The two planes number their accounts independently, so the scope
    /// is the only trustworthy signal — and it is what decides whether the authority fields are
    /// delivered at all.
    /// </summary>
    public bool IsInternal { get; init; }

    /// <summary>A back-office session that has authenticated but not yet chosen a company or
    /// supplier to act as.</summary>
    public bool AwaitingTenantContext { get; init; }

    /// <summary>Whether the member row behind the chosen context holds an admin role. It rides in
    /// the <c>act</c> claim and is the one authority-shaped thing a token legitimately carries,
    /// because it is chosen at context selection rather than computed per request.</summary>
    public bool IsTenantAdmin { get; init; }

    public DateTimeOffset? IssuedAt { get; init; }

    public DateTimeOffset? ExpiresAt { get; init; }
}

/// <summary>
/// What a relying service learns by presenting one of this service's access tokens.
/// <para>
/// <b>The authority collections are three-state and every state means something different.</b> A
/// list is the answer; an empty list is "this caller holds nothing", which closes every gate the
/// relying service has; <see langword="null"/> is "not delivered", which a consumer-plane token
/// gets because the question does not apply to it. A relying service that reads an empty list as
/// null opens itself up; one that reads null as empty locks out every consumer. They are not
/// interchangeable, which is why they are nullable rather than defaulted.
/// </para>
/// </summary>
public sealed record TokenValidationResponse
{
    /// <summary>
    /// Always <see langword="true"/> when this endpoint answers.
    /// <para>
    /// Kept for the Go-era client that branches on it. In the Go service every outcome was HTTP
    /// 200, so this field was the verdict; here an invalid token is a 401 whose <c>errorCode</c>
    /// says which kind of invalid, and this field is the constant that lets those clients keep
    /// their happy path unchanged.
    /// </para>
    /// </summary>
    public bool IsValid { get; init; } = true;

    public required int UserId { get; init; }

    /// <summary>The session this token belongs to. Worth returning: it is what a relying service
    /// quotes back in a support ticket, and what an operator signs out.</summary>
    public string SessionId { get; init; } = string.Empty;

    /// <summary>Whether the caller is a back-office account rather than a consumer.</summary>
    public required bool IsInternal { get; init; }

    /// <summary>Seconds until the token expires, floored at zero.</summary>
    public required long ExpiresIn { get; init; }

    public DateTimeOffset? IssuedAt { get; init; }

    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>The device this session was started on, read from the session row. Empty when the
    /// token carries no session or the row is not tracked here.</summary>
    public string Platform { get; init; } = string.Empty;

    public string DeviceId { get; init; } = string.Empty;

    public required bool IsTenantAdmin { get; init; }

    public ActiveTenantResponse? ActiveTenant { get; init; }

    public IReadOnlyList<string>? Roles { get; init; }

    public IReadOnlyList<string>? Permissions { get; init; }

    public IReadOnlyList<string>? Menus { get; init; }

    /// <summary>Data breadth per tenant dimension. Both dimensions are always declared for a
    /// back-office token, because an absent dimension is read downstream as "unrestricted".</summary>
    public IReadOnlyDictionary<string, ScopeClaim>? Scopes { get; init; }

    /// <summary>
    /// Whether this consumer is on the test-user whitelist, which lets them see and order the test
    /// company's products. It is read from the whitelist store on every call rather than baked into
    /// a token, so adding somebody takes effect on their next request instead of at their next
    /// sign-in.
    /// <para>
    /// <b>Always <see langword="false"/> for a back-office token</b>, where the question does not
    /// apply: the whitelist is keyed by consumer account id, and the two planes number their
    /// accounts independently, so answering it for an internal subject would hand one plane's
    /// entitlement to the other plane's account of the same number.
    /// </para>
    /// <para>
    /// <see langword="false"/> is also what a store that cannot be read degrades to. That hides
    /// test products rather than exposing them - the fail-closed direction, and the one the Go
    /// implementation degraded to as well.
    /// </para>
    /// <para>
    /// A plain <see langword="bool"/> rather than a nullable one, unlike the authority collections
    /// above: the relying services read a missing field as false, so "does not apply" and "no" are
    /// not two states they can tell apart, and pretending otherwise would only invite a null check
    /// nobody writes.
    /// </para>
    /// </summary>
    public bool IsTest { get; init; }
}
