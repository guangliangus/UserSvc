namespace UserSvc.Application.Ports.Iam;

/// <summary>
/// How a permission change reaches sessions that are already open.
/// <para>
/// Two strengths, and the difference matters. A <b>revocation</b> must converge by itself rather
/// than wait for an operator to tick "force reissue": menus and permission points are resolved per
/// request from a cached face, and a point removed from a role stays usable until that cache and
/// the token behind it turn over. A pure <b>addition</b> needs no reissue - the new grant arrives on
/// the next natural refresh, and re-signing every bound member's session for it is churn.
/// </para>
/// </summary>
public interface IAuthzConvergence
{
    /// <summary>Retire every access token these accounts hold, and with it their cached
    /// authorization faces. Used when a change takes something away.</summary>
    Task BumpTokenVersionAsync(IReadOnlyCollection<int> userIds, CancellationToken cancellationToken);

    /// <summary>
    /// Drop the cached authorization faces without touching the tokens.
    /// <para>
    /// Two callers, one meaning. A change that only <b>adds</b> uses it because the new grant needs
    /// no reissue. A change that already incremented <c>token_version</c> inside its own transaction
    /// uses it because the tokens are retired already and only the cached faces are still owed -
    /// calling <see cref="BumpTokenVersionAsync"/> there would increment the counter a second time,
    /// outside that transaction.
    /// </para>
    /// </summary>
    Task InvalidateAuthzAsync(IReadOnlyCollection<int> userIds, CancellationToken cancellationToken);
}
