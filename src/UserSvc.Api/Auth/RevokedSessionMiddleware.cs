using System.Security.Claims;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Api.Auth;

/// <summary>
/// Refuses a request whose session has been revoked, even though its access token is still
/// cryptographically valid and unexpired (decision 11).
/// <para>
/// Without this the revocation set is write-only: signing a device out records the row, records the
/// Redis entry, kills the refresh chain - and the access token already in that device's hands keeps
/// working for the rest of its lifetime. "Sign out this device" that does not sign the device out
/// for another ten minutes is not the feature anyone asked for.
/// </para>
/// <para>
/// The blueprint's end state is the gateway doing this check once and injecting the result, so
/// downstream services pay nothing. This middleware is the same check in the one place it cannot be
/// skipped while no gateway exists; when one lands, deleting this file is the change.
/// </para>
/// <para>
/// It runs after authentication (there is no <c>sid</c> before that) and before authorization (a
/// revoked session must not reach a policy that might approve it). It costs one Redis lookup per
/// authenticated request, which is the price decision 11 accepted for immediate sign-out.
/// </para>
/// </summary>
public sealed class RevokedSessionMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(
        HttpContext context,
        ISessionRevocationStore revocations,
        ILogger<RevokedSessionMiddleware> logger)
    {
        ArgumentNullException.ThrowIfNull(context);

        var sessionId = context.User.FindFirstValue(AuthenticationSchemes.SessionIdClaimType);

        // No sid means no session to revoke: an anonymous request, or a token minted for something
        // other than a device session. Either way there is nothing to look up.
        if (!string.IsNullOrEmpty(sessionId) &&
            await revocations.IsRevokedAsync(sessionId, context.RequestAborted))
        {
            logger.LogInformation(
                "Rejected a request carrying revoked session {SessionId} on {Path}",
                sessionId, context.Request.Path);

            // Thrown rather than written directly, so the response is the same ProblemDetails shape
            // every other failure produces and carries a specific errorCode instead of the generic
            // one the status-code-pages middleware would supply.
            throw new UnauthorizedException(
                ErrorCodes.SessionRevoked,
                "This session has been signed out. Sign in again.");
        }

        await next(context);
    }
}
