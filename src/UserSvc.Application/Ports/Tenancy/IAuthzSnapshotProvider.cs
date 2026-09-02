using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Ports.Tenancy;

/// <summary>The cached authority surface of one session.</summary>
public sealed record AuthzSnapshot(
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> Menus,
    IReadOnlyDictionary<string, ScopeClaim> Scopes);

/// <summary>
/// The per-request authorization snapshot, cached in Redis.
/// <para>
/// Deliberately optional at the point of use: the shell endpoint tolerates this being absent or
/// failing, and reports "not delivered" (null) rather than "you have nothing" (empty). The two
/// look alike in JSON and mean opposite things to the front end - empty closes every gated route,
/// absent leaves the session as it was.
/// </para>
/// </summary>
public interface IAuthzSnapshotProvider
{
    Task<AuthzSnapshot> GetOrComputeAsync(
        int userId, ActClaim act, int tokenVersion, CancellationToken cancellationToken);

    /// <summary>Routable paths for the given menu codes. Null on failure - the front end then
    /// falls back to its static map, which is why this must never degrade to an empty list.</summary>
    Task<IReadOnlyList<MenuRoute>?> MenuRoutesForCodesAsync(
        IReadOnlyCollection<string> menuCodes, CancellationToken cancellationToken);
}

/// <summary>A menu code and the front-end path it routes to.</summary>
public sealed record MenuRoute(string Code, string Path);
