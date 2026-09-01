using System.Collections.Concurrent;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Infrastructure.Platform;

/// <summary>
/// <b>Placeholder — local development only.</b> The real implementation is Redis (decision 11).
/// <para>
/// A placeholder must pick the safe side, and here the safe side is not "work quietly": a
/// per-instance in-memory set <b>does not propagate revocations</b> across replicas, so a device
/// kicked on one pod sails through on another. It therefore <b>refuses to register</b> outside
/// Development (see <c>DependencyInjection</c>) — failing to start beats shipping a revocation
/// mechanism that looks fine and silently misses half the traffic.
/// </para>
/// </summary>
public sealed class InMemorySessionRevocationStore : ISessionRevocationStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _revoked = new(StringComparer.Ordinal);

    public Task RevokeAsync(string sessionId, TimeSpan ttl, CancellationToken cancellationToken)
    {
        _revoked[sessionId] = DateTimeOffset.UtcNow.Add(ttl);
        return Task.CompletedTask;
    }

    public Task<bool> IsRevokedAsync(string sessionId, CancellationToken cancellationToken)
    {
        if (!_revoked.TryGetValue(sessionId, out var expiresAt))
        {
            return Task.FromResult(false);
        }

        if (DateTimeOffset.UtcNow >= expiresAt)
        {
            _revoked.TryRemove(sessionId, out _);
            return Task.FromResult(false);
        }

        return Task.FromResult(true);
    }
}
