using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Features.BackOffice.Tenants;

/// <summary>
/// Where a session is currently acting, as the shell renders it.
/// <para>
/// A supplier context also reports the company its supplier is mounted on, because the shell shows
/// both and the mount is only knowable from the data-scope envelope, not from the act claim.
/// </para>
/// </summary>
public sealed record ActiveTenantResponse
{
    /// <summary>platform | global | company | supplier.</summary>
    public required string Type { get; init; }

    public string CompanyCode { get; init; } = string.Empty;

    public string SupplierCode { get; init; } = string.Empty;

    /// <summary>For a whole-dimension context, which dimension was chosen.</summary>
    public string Dimension { get; init; } = string.Empty;
}

/// <summary>One entry of the context switcher.</summary>
public sealed record TenantSummaryResponse
{
    public required string TenantType { get; init; }

    /// <summary><see cref="TenantScopes.ScopeAllSentinelCode"/> for a whole-dimension entry.</summary>
    public required string TenantCode { get; init; }

    /// <summary>Localized names by locale tag. Null when the master data does not know this code,
    /// or could not be reached - the shell then shows the code rather than an invented name.</summary>
    public IReadOnlyDictionary<string, string>? TenantName { get; init; }

    public bool ScopeAll { get; init; }

    public bool IsAdmin { get; init; }

    public string DeptName { get; init; } = string.Empty;
}

/// <summary>The contexts this session may choose from.</summary>
public sealed record TenantListResponse
{
    /// <summary>Null before a context has been chosen.</summary>
    public ActiveTenantResponse? ActiveTenant { get; init; }

    /// <summary>Whether this account holds whole-dimension access anywhere - the super
    /// administrator flag counts.</summary>
    public required bool IsGlobal { get; init; }

    public IReadOnlyList<TenantSummaryResponse> Tenants { get; init; } = [];
}

/// <summary>
/// Choose a context.
/// <para>
/// <see cref="TenantCode"/> may be <see cref="TenantScopes.ScopeAllSentinelCode"/>, which asks for
/// the whole dimension rather than for one tenant. That request is authorized by standing, not by
/// a member row, so it takes a different path entirely.
/// </para>
/// </summary>
public sealed record SelectTenantContextRequest
{
    /// <summary>company | supplier. There is no platform option: the platform super administrator
    /// enters that context at sign-in and has nothing to choose.</summary>
    public string TenantType { get; init; } = string.Empty;

    public string TenantCode { get; init; } = string.Empty;
}

/// <summary>
/// The authority surface of a chosen context.
/// <para>
/// Roles, permissions, menus and scopes travel in the <b>body</b>, never in the token. A token is
/// an identity ticket here; keeping the computed surface out of it is what makes a permission
/// taken away stop working on the next request instead of at the next sign-in.
/// </para>
/// <para>
/// Every collection is always present, empty when there is nothing. An empty list and a missing
/// field look alike in JSON and mean opposite things to the shell: empty closes the gate, missing
/// is read as "this build does not gate" and opens it.
/// </para>
/// </summary>
public sealed record TenantContextResponse
{
    public ActiveTenantResponse? ActiveTenant { get; init; }

    public required bool IsTenantAdmin { get; init; }

    public IReadOnlyList<string> Roles { get; init; } = [];

    public IReadOnlyList<string> Permissions { get; init; } = [];

    public IReadOnlyList<string> Menus { get; init; } = [];

    public IReadOnlyDictionary<string, ScopeClaim> Scopes { get; init; } =
        TenantContextResult.EmptyScopeEnvelope();
}

/// <summary>The signed-in account, as the shell header renders it.</summary>
public sealed record BackOfficeUserResponse
{
    public required int Id { get; init; }

    public string FirstName { get; init; } = string.Empty;

    public string LastName { get; init; } = string.Empty;

    /// <summary>The same display name rule the roster uses.</summary>
    public string Nickname { get; init; } = string.Empty;

    public string StaffCode { get; init; } = string.Empty;

    public string Status { get; init; } = string.Empty;

    public DateTimeOffset? LastLoginAt { get; init; }
}

/// <summary>
/// Everything the shell needs to draw itself.
/// <para>
/// The authority collections are <b>nullable on purpose</b>, and the three states are all
/// meaningful: a list is the answer, an empty list is "you have none", and null is "not delivered
/// this time". This endpoint is the front end's resynchronisation source, so a transient snapshot
/// failure must not read as "your permissions were revoked" - it leaves the session as it is.
/// </para>
/// </summary>
public sealed record BackOfficeMeResponse
{
    public required BackOfficeUserResponse User { get; init; }

    /// <summary>INTERNAL | EXTERNAL. It decides whether a password reset is even possible.</summary>
    public required string Origin { get; init; }

    public ActiveTenantResponse? ActiveTenant { get; init; }

    /// <summary>Whether the member row behind the active tenant context holds an admin role.
    /// False in a global or platform context: a dimension has no administrator seat.</summary>
    public required bool IsTenantAdmin { get; init; }

    public required bool IsGlobal { get; init; }

    public IReadOnlyList<string>? Roles { get; init; }

    public IReadOnlyList<string>? Permissions { get; init; }

    public IReadOnlyList<string>? Menus { get; init; }

    public IReadOnlyDictionary<string, ScopeClaim>? Scopes { get; init; }

    /// <summary>Null means "not delivered" and lets the shell fall back to its static route map;
    /// an empty list means "nothing is routable" and closes every gated route. A menu-service
    /// hiccup must produce the first, never the second.</summary>
    public IReadOnlyList<MenuRoute>? MenuRoutes { get; init; }

    public IReadOnlyList<TenantSummaryResponse> Tenants { get; init; } = [];
}
