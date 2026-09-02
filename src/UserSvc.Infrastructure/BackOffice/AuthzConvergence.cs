using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Iam;
using UserSvc.Infrastructure.Platform;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// How a permission change reaches sessions that are already open: the token-version column for the
/// strong form, the snapshot cache for the weak one.
/// <para>
/// <b>The two methods are not interchangeable and the difference is measured in what a caller can
/// still do.</b> Bumping the version retires every access token the account holds, so a revocation
/// converges by itself instead of waiting for somebody to tick "force reissue". Dropping the cached
/// face alone leaves the tokens alive and simply makes the next request recompute, which is exactly
/// right for a pure addition - re-signing every bound member's session to hand them something extra
/// is churn, and the grant arrives on the next natural refresh anyway.
/// </para>
/// <para>
/// The strong form does both: a token version bump with a live cached face behind it would leave
/// the removed permission usable for the cache's whole lifetime, which is the failure the bump was
/// meant to prevent.
/// </para>
/// </summary>
public sealed class AuthzConvergence(
    IBackendUserRepository users,
    RedisAuthzSnapshotCache cache) : IAuthzConvergence
{
    public async Task BumpTokenVersionAsync(
        IReadOnlyCollection<int> userIds, CancellationToken cancellationToken)
    {
        if (userIds.Count == 0)
        {
            return;
        }

        await users.IncrementTokenVersionAsync([.. userIds.Distinct()], cancellationToken);
        await cache.InvalidateAsync([.. userIds], cancellationToken);
    }

    public Task InvalidateAuthzAsync(IReadOnlyCollection<int> userIds, CancellationToken cancellationToken) =>
        userIds.Count == 0
            ? Task.CompletedTask
            : cache.InvalidateAsync([.. userIds], cancellationToken);
}
