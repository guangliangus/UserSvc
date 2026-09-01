using OpenIddict.Abstractions;
using OpenIddict.Server;
using UserSvc.Application.Features.Sessions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace UserSvc.Api.Auth;

/// <summary>
/// Raises <c>user.refresh-token-replayed.v1</c> when a redeemed refresh token is presented again.
/// <para>
/// It has to be a server event handler, and it cannot live in <see cref="Controllers.TokenController"/>.
/// With <c>EnableTokenEndpointPassthrough</c> OpenIddict validates the grant <b>before</b> the
/// controller action runs and answers a rejected refresh token itself with a 400, so
/// <c>Exchange</c> never executes on a replay — replay detection written there would be dead code
/// that looks alive.
/// </para>
/// <para>
/// The order is the whole trick. The dispatcher stops the moment a handler rejects the context, so
/// a handler placed <i>after</i> OpenIddict's <c>ValidateTokenEntry</c> would never run on the one
/// request it exists for. This one runs immediately <b>before</b> it, once the token entry has been
/// resolved and the principal decrypted, and reads the same token row that is about to be refused.
/// Matching on the rejection's error string instead would have been a contract nobody promised us.
/// </para>
/// <para>
/// Detecting the replay is all it does. Killing the rest of the chain is OpenIddict's own doing,
/// and only because <c>SetRefreshTokenReuseLeeway(TimeSpan.Zero)</c> is set — see
/// <see cref="OpenIddictRegistration"/>.
/// </para>
/// </summary>
public sealed class RefreshTokenReplayHandler(
    IOpenIddictTokenManager tokens,
    SessionAppService sessions,
    ILogger<RefreshTokenReplayHandler> logger) : IOpenIddictServerHandler<ValidateTokenContext>
{
    /// <summary>Registered through <c>options.AddEventHandler(RefreshTokenReplayHandler.Descriptor)</c>.
    /// Scoped, because <see cref="SessionAppService"/> and the token manager both are.</summary>
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseScopedHandler<RefreshTokenReplayHandler>()
            .SetOrder(OpenIddictServerHandlers.Protection.ValidateTokenEntry.Descriptor.Order - 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // The same event validates access tokens, client assertions and everything else OpenIddict
        // reads. Only a refresh token presented at the token endpoint can be a chain replay.
        // Note the constant: at 7.6.1 ValidTokenTypes carries TokenTypeIdentifiers values (the
        // urn:ietf:... form), NOT the TokenTypeHints values the RFC 7009 hint parameter uses. Both
        // are named RefreshToken and picking the wrong one silently disables this handler, which is
        // a failure with no symptom - the replay is still refused, the alert simply never fires.
        if (context.EndpointType is not OpenIddictServerEndpointType.Token ||
            context.Request?.IsRefreshTokenGrantType() is not true ||
            !context.ValidTokenTypes.Contains(TokenTypeIdentifiers.RefreshToken))
        {
            return;
        }

        // No entry resolved means the token is unknown or malformed - a refusal, but not evidence
        // that a token ever leaked.
        if (string.IsNullOrEmpty(context.TokenId))
        {
            return;
        }

        var token = await tokens.FindByIdAsync(context.TokenId, context.CancellationToken);
        if (token is null)
        {
            return;
        }

        // "Redeemed" is the whole signal: this exact token was already traded in for a newer one.
        // An expired or revoked token is refused too, and neither means a leak.
        if (!await tokens.HasStatusAsync(token, Statuses.Redeemed, context.CancellationToken))
        {
            return;
        }

        var sessionId = context.Principal?.GetClaim(AuthenticationSchemes.SessionIdClaimType);
        if (string.IsNullOrEmpty(sessionId))
        {
            logger.LogWarning(
                "A redeemed refresh token was replayed but carried no {ClaimType} claim, so no session could be revoked.",
                AuthenticationSchemes.SessionIdClaimType);
            return;
        }

        logger.LogWarning(
            "Refresh token replay detected for session {SessionId}; revoking the session.", sessionId);

        if (!await sessions.HandleRefreshTokenReplayAsync(sessionId, context.CancellationToken))
        {
            // The replay is refused either way, so nothing here is visible to the client - which is
            // exactly why it has to be visible in the log. No session row means no outbox alert and
            // no revocation entry: a token that leaked left no trace but this line.
            logger.LogError(
                "Refresh token replay for session {SessionId} could not be recorded: no session row "
                + "carries that {ClaimType}.",
                sessionId,
                AuthenticationSchemes.SessionIdClaimType);
        }
    }
}
