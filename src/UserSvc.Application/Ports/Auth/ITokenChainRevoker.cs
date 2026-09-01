namespace UserSvc.Application.Ports.Auth;

/// <summary>
/// Kills every token issued under one OpenIddict authorization — the refresh chain of a single
/// device session (decision 10).
/// <para>
/// It is a port because the token rows live behind the OpenIddict stores, which the application
/// layer must not reference: <c>IOpenIddictTokenManager</c> would drag the protocol stack into the
/// inner ring. Revoking the <see cref="UserSvc.Domain.Auth.UserSession"/> row alone is not enough
/// — that stops the <i>next</i> refresh from being accepted by our own check, but the refresh
/// token itself would still be a valid credential to OpenIddict.
/// </para>
/// </summary>
public interface ITokenChainRevoker
{
    /// <summary>Revoke every token row sharing <paramref name="authorizationId"/>. Must be a no-op
    /// for an empty id and must not fail when the chain is already gone.</summary>
    Task RevokeChainAsync(string authorizationId, CancellationToken cancellationToken);
}
