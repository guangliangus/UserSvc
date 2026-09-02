using Microsoft.Extensions.Logging;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;
using UserSvc.Infrastructure.Platform;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// The per-request authority snapshot: the tenant context funnel, memoised in Redis.
/// <para>
/// It computes nothing of its own. <see cref="TenantContextAppService.ComputeAsync"/> is the single
/// funnel that decides what a context resolves to, and sign-in, a context switch and this cache all
/// go through it precisely so they cannot drift apart. <b>Recomputation is itself the legality
/// check</b>: it re-reads standing from the database and never trusts the presented <c>act</c>, so a
/// context an account has since lost comes back empty rather than frozen into a token.
/// </para>
/// <para>
/// The cached entry carries the <c>token_version</c> it was computed from, read from the account
/// row rather than from any cached copy of it. A cached copy can lag a bump by a whole TTL, which
/// would make every freshly refreshed token treat its own snapshot as stale and recompute on every
/// single request.
/// </para>
/// </summary>
public sealed class AuthzSnapshotProvider(
    TenantContextAppService contexts,
    IBackendUserRepository users,
    IMenuRepository menus,
    RedisAuthzSnapshotCache cache,
    ILogger<AuthzSnapshotProvider> logger) : IAuthzSnapshotProvider
{
    /// <summary>Characters that make a menu path unusable as a route: the front end splits its
    /// pairs on the bar, and whitespace can only be a data-entry mistake.</summary>
    private static readonly char[] ForbiddenInPath = [' ', '\t', '|'];

    public async Task<AuthzSnapshot> GetOrComputeAsync(
        int userId, ActClaim act, int tokenVersion, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(act);

        var key = cache.KeyFor(userId, act);

        var cached = await cache.ReadAsync(key, cancellationToken);
        if (cached is not null && cached.Ver >= tokenVersion)
        {
            return new AuthzSnapshot(cached.Roles, cached.Permissions, cached.Menus, cached.Scopes);
        }

        var result = await contexts.ComputeAsync(userId, act, cancellationToken);

        // The version is stamped from the row the computation was based on. A snapshot that claimed
        // a newer version than it was computed from would outlive the very bump meant to retire it.
        var account = await users.ReadByIdAsync(userId, cancellationToken);

        var snapshot = new CachedAuthzSnapshot(
            account?.TokenVersion ?? tokenVersion,
            result.Roles,
            result.Permissions,
            result.Menus,
            result.Scopes);

        await cache.WriteAsync(userId, key, snapshot, cancellationToken);

        return new AuthzSnapshot(snapshot.Roles, snapshot.Permissions, snapshot.Menus, snapshot.Scopes);
    }

    /// <summary>
    /// Menu codes resolved to front-end paths, or null when they could not be resolved at all.
    /// <b>Null and empty mean opposite things here</b> - null lets the front end fall back to its
    /// static map, empty tells it this account routes nowhere - so a failure must never degrade into
    /// an empty list.
    /// </summary>
    public async Task<IReadOnlyList<MenuRoute>?> MenuRoutesForCodesAsync(
        IReadOnlyCollection<string> menuCodes, CancellationToken cancellationToken)
    {
        if (menuCodes.Count == 0)
        {
            return [];
        }

        IReadOnlyList<Domain.Iam.Menu> rows;
        try
        {
            rows = await menus.ListByCodesAsync(menuCodes, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Menu routes could not be resolved; reporting them as undelivered.");
            return null;
        }

        var routes = new List<MenuRoute>(rows.Count);

        foreach (var menu in rows)
        {
            if (!menu.IsActive())
            {
                continue;
            }

            var path = (menu.Path ?? string.Empty).Trim();
            if (path.Length == 0)
            {
                // A grouping container with no page behind it. Not this gate's business.
                continue;
            }

            if (!path.StartsWith('/') || path.IndexOfAny(ForbiddenInPath) >= 0)
            {
                // Dropped rather than passed through: a missing pair fails closed and is visible
                // immediately, while a malformed one points the route gate at a page that does not
                // exist and looks like a front-end bug for a week.
                logger.LogWarning(
                    "Dropping menu {MenuCode} from the route map: its path {MenuPath} is malformed.",
                    menu.Code,
                    path);

                continue;
            }

            routes.Add(new MenuRoute(menu.Code, path.Length > 1 ? path.TrimEnd('/') : path));
        }

        return [.. routes.OrderBy(route => route.Code, StringComparer.Ordinal)];
    }
}
