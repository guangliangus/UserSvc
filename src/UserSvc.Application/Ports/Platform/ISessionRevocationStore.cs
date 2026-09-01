namespace UserSvc.Application.Ports.Platform;

/// <summary>
/// The session revocation set (decision 11). Keyed by <c>sid</c>, with a <b>TTL equal to the
/// access-token lifetime</b> — so the set only ever holds sessions revoked in the last few
/// minutes. It never grows and needs no cleanup job.
/// <para>
/// Callers must <b>fail open</b> when a read fails: this is an extra check layered on top of a
/// token that has already passed full signature validation, and the short token lifetime is the
/// fallback. (Contrast: a failed permission lookup must fail closed.)
/// </para>
/// </summary>
public interface ISessionRevocationStore
{
    Task RevokeAsync(string sessionId, TimeSpan ttl, CancellationToken cancellationToken);

    Task<bool> IsRevokedAsync(string sessionId, CancellationToken cancellationToken);
}
