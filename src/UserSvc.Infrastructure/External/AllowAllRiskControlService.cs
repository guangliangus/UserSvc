using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.External;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The stand-in for adaptive risk control until a CAPTCHA provider is configured. It exists so the
/// calling logic - the send-code orchestration, the API contract, the error codes - can be written
/// once, in full, against a port that already has the shape the real adapter will have.
/// <para>
/// <b>Its three methods do not all answer the same way, and that is the design.</b> "Placeholder"
/// is not a licence to approve everything; for a security component the placeholder must fall on
/// the refusing side of every question whose answer it cannot actually compute. Which side that is
/// depends on what the answer grants:
/// </para>
/// <list type="bullet">
/// <item>
/// <b><see cref="EvaluateSendCodeAsync"/> allows.</b> This one is not a security decision that can
/// be refused - it is a throttle, and the port already promises that a counting failure degrades to
/// Allow. Answering CaptchaRequired instead would be strictly worse than refusing: nothing here can
/// issue a CAPTCHA token, so every user would be sent to solve a challenge that can never be
/// redeemed, and send-code would be dead rather than merely unthrottled. The per-IP rate limiter in
/// front of the endpoint is what stands in for this in the meantime.
/// </item>
/// <item>
/// <b><see cref="TryConsumeCaptchaTokenAsync"/> refuses.</b> Returning true would honour a
/// CAPTCHA token that no provider ever assessed, from any client that guessed the field name -
/// turning the bypass into a header anyone can send. False is the safe answer and costs nothing
/// today, because nothing issues tokens for it to reject.
/// </item>
/// <item>
/// <b><see cref="VerifyCaptchaAsync"/> throws.</b> This is the method the earlier port's own notes
/// flagged: an implementation that "always allows" would mint a real, redeemable bypass token for
/// an unverified provider answer. The CAPTCHA gate would then be silently absent while every
/// response still said it had been passed - the worst of the three outcomes, because it looks like
/// it works. A 500 is loud, honest and impossible to mistake for a pass.
/// </item>
/// </list>
/// </summary>
public sealed class PlaceholderRiskControlService(ILogger<PlaceholderRiskControlService> logger)
    : IRiskControlService
{
    public Task<SendCodeRiskDecision> EvaluateSendCodeAsync(
        SendCodeRiskContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        // Deliberately silent. This runs on every send-code request, and a warning per request
        // would bury the one below - which is the line that actually indicates something unusual.
        return Task.FromResult(SendCodeRiskDecision.Allow());
    }

    public Task<bool> TryConsumeCaptchaTokenAsync(
        string captchaToken,
        SendCodeRiskContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if (!string.IsNullOrWhiteSpace(captchaToken))
        {
            // Nothing in this deployment issues CAPTCHA tokens, so a client presenting one is
            // either probing for the bypass or running against a stale build. Either is worth a
            // line; neither is worth an exception, because the caller's fallback - re-evaluate the
            // throttle - is the correct handling of an unusable token.
            logger.LogWarning(
                "A CAPTCHA token was presented for target type {TargetType}, but no CAPTCHA "
                + "provider is configured, so no token can be valid. Refusing the bypass.",
                context.TargetType);
        }

        return Task.FromResult(false);
    }

    public Task<CaptchaVerificationResult> VerifyCaptchaAsync(
        CaptchaVerificationContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        logger.LogError(
            "CAPTCHA verification was requested for region {Region} on platform {Platform}, but no "
            + "provider is configured. Either the endpoint should not be routed yet, or the "
            + "provider credentials are missing from this environment.",
            context.Region,
            context.Platform);

        // 500, not 502: nothing upstream failed - we never asked anyone. This is our own missing
        // configuration, and calling it a bad gateway would point the investigation at an innocent
        // third party. The message is safe to return; the detail stays in the log above.
        throw new AppException(
            ErrorCodes.InternalError,
            "Captcha verification is not available on this deployment.",
            500);
    }
}
