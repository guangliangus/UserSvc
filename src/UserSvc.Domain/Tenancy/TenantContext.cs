namespace UserSvc.Domain.Tenancy;

/// <summary>
/// The kinds of active context a back-office session can run in. Uppercase, because these travel
/// in the <c>act</c> claim and the back office switches on them verbatim.
/// </summary>
public static class ActTypes
{
    /// <summary>The platform super administrator. Reaches both dimensions, chooses nothing at
    /// sign-in, and is deliberately exclusive with holding tenant roles.</summary>
    public const string Platform = "PLATFORM";

    /// <summary>A whole dimension - every company, or every supplier. Which one is carried by
    /// <see cref="ActClaim.Dimension"/>.</summary>
    public const string Global = "GLOBAL";

    public const string Company = "COMPANY";

    public const string Supplier = "SUPPLIER";

    public static bool IsKnown(string? actType) =>
        actType is Platform or Global or Company or Supplier;

    /// <summary>The act type a tenant dimension maps to.</summary>
    public static string ForTenantType(string tenantType) =>
        tenantType == TenantTypes.Supplier ? Supplier : Company;

    /// <summary>The tenant dimension an act type maps back to.</summary>
    public static string ToTenantType(string actType) =>
        actType == Supplier ? TenantTypes.Supplier : TenantTypes.Company;
}

/// <summary>
/// Which context a session is acting in. This is the <b>only</b> computed thing that belongs in a
/// token: roles, permissions, menus and data scopes are all recomputed per request and travel in
/// response bodies, so that a permission taken away is gone on the next call rather than on the
/// next sign-in.
/// </summary>
/// <param name="Type">One of <see cref="ActTypes"/>.</param>
/// <param name="Code">The company or supplier code for a tenant context; empty otherwise.</param>
/// <param name="Dimension">For <see cref="ActTypes.Global"/>, the dimension chosen at sign-in
/// (<c>company</c> or <c>supplier</c>). Empty means a token minted before dimension selection
/// existed, which keeps its old both-dimensions behaviour until it expires.</param>
/// <param name="IsAdmin">Whether the member row behind a tenant context holds an admin role. It is
/// what the back office renders its "administrator" affordances from.</param>
public sealed record ActClaim(
    string Type,
    string Code = "",
    string Dimension = "",
    bool IsAdmin = false);

/// <summary>
/// The data-scope envelope for one dimension: the tenant codes this session may read, or a flag
/// saying "all of them".
/// <para>
/// An <b>absent</b> dimension is read downstream as "unrestricted", so every context declares both
/// dimensions explicitly - an empty <see cref="Values"/> with <see cref="IsGlobal"/> false is the
/// way to say "none", and it is not the same thing as leaving the entry out.
/// </para>
/// </summary>
public sealed record ScopeClaim(IReadOnlyList<string> Values, bool IsGlobal)
{
    public static ScopeClaim None { get; } = new([], false);

    public static ScopeClaim Global { get; } = new([], true);
}

/// <summary>
/// Everything a context resolves to. Produced by one funnel so that sign-in, refresh, a context
/// switch and a per-request authorization snapshot cannot drift apart.
/// </summary>
public sealed record TenantContextResult
{
    /// <summary>Null when the account carries no authority at all - a disabled or not-yet-onboarded
    /// account, which is allowed to hold a session that simply carries nothing.</summary>
    public ActClaim? Act { get; init; }

    public IReadOnlyList<string> Roles { get; init; } = [];

    public IReadOnlyList<string> Permissions { get; init; } = [];

    /// <summary>Menu codes. Empty is a real answer ("you may see nothing"); the code never lets
    /// this be null, because a missing menu list is read by the front end as "this backend does
    /// not gate menus" and opens everything.</summary>
    public IReadOnlyList<string> Menus { get; init; } = [];

    /// <summary>Both dimensions, always present. See <see cref="ScopeClaim"/>.</summary>
    public IReadOnlyDictionary<string, ScopeClaim> Scopes { get; init; } = EmptyScopeEnvelope();

    /// <summary>Both dimensions declared and empty - the shape a no-access context reports.</summary>
    public static IReadOnlyDictionary<string, ScopeClaim> EmptyScopeEnvelope() =>
        new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
        {
            [TenantTypes.Company] = ScopeClaim.None,
            [TenantTypes.Supplier] = ScopeClaim.None,
        };

    /// <summary>The context of an account that may hold a session but carries no authority.</summary>
    public static TenantContextResult NoAccess() => new();
}
