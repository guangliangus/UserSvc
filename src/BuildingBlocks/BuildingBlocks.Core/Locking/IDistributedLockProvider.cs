namespace BuildingBlocks.Core.Locking;

/// <summary>
/// Cross-replica mutual exclusion. The Redis implementation is a single-instance lock
/// (SET NX PX + token-checked release): correct for coordination and dedup, not for
/// workloads that need fencing tokens.
/// </summary>
public interface IDistributedLockProvider
{
    /// <summary>
    /// Tries to acquire <paramref name="resource"/> for <paramref name="ttl"/>, retrying until
    /// <paramref name="wait"/> elapses (no retry when null). Returns null when not acquired.
    /// Dispose the handle to release early; the TTL bounds the hold on crash.
    /// </summary>
    Task<IAsyncDisposable?> TryAcquireAsync(
        string resource,
        TimeSpan ttl,
        TimeSpan? wait = null,
        CancellationToken cancellationToken = default);
}
