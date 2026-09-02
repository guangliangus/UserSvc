using UserSvc.Domain.Iam;

namespace UserSvc.Application.Ports.Iam;

/// <summary>
/// Who is calling, and what they effectively hold. Populated by the API layer from the validated
/// token plus the resolved authorization face; the application layer sees neither HTTP nor JWT.
/// <para>
/// <b>The access token is an identity ticket only</b> - it carries no roles, permissions, scopes or
/// menus. Anything that reads authority out of token claims is a porting mistake.
/// </para>
/// </summary>
public interface IBackOfficeCaller
{
    /// <summary>The caller's account id, or 0 when there is none. Zero is a real answer everywhere
    /// in this module: a narrowing read that treats "no caller" as "the platform" is exactly how an
    /// endpoint turns into a platform-wide directory.</summary>
    int UserId { get; }

    string Nickname { get; }

    /// <summary>The acting context: PLATFORM, COMPANY, SUPPLIER or GLOBAL. See
    /// <see cref="ActTypes"/>.</summary>
    string ActType { get; }

    /// <summary>The tenant code being acted as, or the <c>*</c> sentinel for a whole dimension.</summary>
    string ActCode { get; }

    /// <summary>For a GLOBAL act, which dimension was chosen at sign-in. Empty on a token minted
    /// before dimension selection existed, which means both.</summary>
    string ActDim { get; }

    string? IpAddress { get; }

    string? RequestId { get; }

    /// <summary>
    /// What the caller effectively holds, resolved per request.
    /// <para>
    /// When the resolution is missing this must answer an <b>empty</b> face rather than go and
    /// compute one: fail closed at the point where closing is right, and never let a service reach
    /// around the request pipeline for authority.
    /// </para>
    /// </summary>
    EffectiveAuthz Authz { get; }
}

/// <summary>
/// The caller's resolved authorization face: what they can see and do right now. <c>Scopes</c> is
/// data breadth per tenant dimension, and breadth is never authority.
/// </summary>
public sealed record EffectiveAuthz(
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> Menus,
    IReadOnlyDictionary<string, ScopeClaim> Scopes)
{
    /// <summary>The fail-closed default: holds nothing, sees nothing.</summary>
    public static EffectiveAuthz Empty { get; } =
        new([], [], [], new Dictionary<string, ScopeClaim>(StringComparer.Ordinal));

    /// <summary>The claim for one dimension, or an empty one when the dimension is absent.</summary>
    public ScopeClaim ScopeFor(string tenantType) =>
        Scopes.TryGetValue(tenantType, out var claim) ? claim : ScopeClaim.Empty;
}
