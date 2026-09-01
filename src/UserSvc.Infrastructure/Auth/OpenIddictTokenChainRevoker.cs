using OpenIddict.Abstractions;
using UserSvc.Application.Ports.Auth;

namespace UserSvc.Infrastructure.Auth;

/// <summary>
/// Implements <see cref="ITokenChainRevoker"/> on OpenIddict's token store (decision 10).
/// <para>
/// Every token OpenIddict issues for one device session carries the same authorization id, so
/// revoking by that id is what turns "this session is revoked" into "this refresh token is no
/// longer a credential". It marks rows revoked rather than deleting them; the audit trail of what
/// was issued when is worth more than the rows cost, and
/// <see cref="OpenIddictPruningService"/> clears them out later.
/// </para>
/// </summary>
public sealed class OpenIddictTokenChainRevoker(IOpenIddictTokenManager tokens) : ITokenChainRevoker
{
    public async Task RevokeChainAsync(string authorizationId, CancellationToken cancellationToken)
    {
        // Sessions created before the authorization id was recorded carry an empty one. Passing
        // that to the store would match nothing at best and everything at worst.
        if (string.IsNullOrWhiteSpace(authorizationId))
        {
            return;
        }

        await tokens.RevokeByAuthorizationIdAsync(authorizationId, cancellationToken);
    }
}
