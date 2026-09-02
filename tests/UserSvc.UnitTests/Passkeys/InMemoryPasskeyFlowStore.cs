using System.Collections.Concurrent;
using UserSvc.Infrastructure.Auth;

namespace UserSvc.UnitTests.Passkeys;

/// <summary>
/// The ceremony store without a Redis. It reproduces the two behaviours the ceremony depends on -
/// single use, and a miss for anything unknown - and nothing else.
/// <para>
/// Substituting the store rather than the verifier is the whole point of
/// <see cref="IPasskeyFlowStore"/> being a seam: everything below it in
/// <see cref="Fido2WebAuthnCeremony"/> is the real cryptography, exercised for real by these tests.
/// </para>
/// </summary>
internal sealed class InMemoryPasskeyFlowStore : IPasskeyFlowStore
{
    private readonly ConcurrentDictionary<string, PasskeyFlow> _flows = new(StringComparer.Ordinal);

    /// <summary>How many flows are still outstanding, so a test can assert that a finished
    /// ceremony left nothing behind.</summary>
    public int Count => _flows.Count;

    public Task StoreAsync(string flowId, PasskeyFlow flow, TimeSpan ttl, CancellationToken cancellationToken)
    {
        _flows[flowId] = flow;
        return Task.CompletedTask;
    }

    public Task<PasskeyFlow?> TakeAsync(string flowId, CancellationToken cancellationToken) =>
        Task.FromResult(_flows.TryRemove(flowId, out var flow) ? flow : null);
}
