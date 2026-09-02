using UserSvc.Application.Ports.Tenancy;
using UserSvc.Infrastructure.Platform;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// Drops one account's cached authority surface after a membership change.
/// <para>
/// <b>It goes to Redis, not to <c>iam.backend_users.token_version</c>, and the choice is forced by
/// the call sites.</b> Every one of them already calls
/// <c>IBackOfficeAccountDirectory.IncrementTokenVersionAsync</c> on the line above - the column is
/// bumped inside the transaction, where it belongs, because it is a row the change is part of.
/// Bumping it a second time here would double-increment the generation counter and, worse, would do
/// it after the commit, so the two writes could interleave with a concurrent change and lose one.
/// </para>
/// <para>
/// What is left over is the copy of that authority surface living in Redis, which nothing in the
/// transaction can reach: the column says "your token is old" but the cached face is what a request
/// actually reads, and it would keep answering with the pre-change permissions for the rest of its
/// TTL. This port is the seam that clears it, which is why it is named for the cache and not for
/// the column.
/// </para>
/// </summary>
public sealed class AuthzSnapshotTokenVersionCache(RedisAuthzSnapshotCache cache) : ITokenVersionCache
{
    public Task InvalidateAsync(int userId, CancellationToken cancellationToken) =>
        cache.InvalidateAsync([userId], cancellationToken);
}
