using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Verification;
using UserSvc.Application.Ports.External;

namespace UserSvc.Application.Features.RiskControl;

/// <summary>
/// The verify half of the CAPTCHA escalation: a client that was refused with
/// <c>CAPTCHA_REQUIRED</c> runs the provider's SDK, posts the resulting token here, and gets back a
/// one-time credential to replay its send-code request with.
/// <para>
/// <b>This service is a mapper, not a policy.</b> Everything that decides anything - the provider
/// assessment, the failure counting, the cooldown, the minting and binding of the token - lives
/// behind <see cref="IRiskControlService"/>, because all of it needs the same Redis state the
/// send-code path reads and none of it can be tested here. What is left is the three facts the
/// port cannot get for itself: which region assesses, which platform's key to use, and what the
/// caller looks like from the network.
/// </para>
/// <para>
/// <b>There is no user lookup on this path and there must never be one.</b> The endpoint is public
/// and takes an arbitrary address; answering differently for an address that exists would turn a
/// CAPTCHA endpoint into the enumeration oracle the send-code path is already criticised for
/// having. A token minted for an address nobody has registered is harmless - it unblocks a send
/// that will fail its own purpose precondition.
/// </para>
/// </summary>
public sealed class CaptchaAppService(IRiskControlService riskControl, IOptions<RiskControlOptions> options)
{
    private readonly RiskControlOptions _options = options.Value;

    /// <summary>
    /// Assess the provider token and, if it holds up, issue the bypass token bound to this exact
    /// target and device.
    /// </summary>
    public async Task<CaptchaVerifyResponse> VerifyAsync(
        CaptchaVerifyRequest request,
        CaptchaRequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);

        Validate(request);

        var result = await riskControl.VerifyCaptchaAsync(
            new CaptchaVerificationContext(
                request.Answer.Trim(),
                request.Target,
                request.TargetType,
                context.DeviceId,
                CaptchaRegions.Resolve(_options.AppRegion, context.Language),
                CaptchaPlatforms.Normalize(context.Platform),
                NullIfBlank(context.ClientIpAddress),
                NullIfBlank(context.UserAgent)),
            cancellationToken);

        return new CaptchaVerifyResponse
        {
            CaptchaToken = result.CaptchaToken,
            ExpiresIn = (int)result.ExpiresIn.TotalSeconds,
        };
    }

    /// <summary>
    /// The longest provider token this endpoint will forward.
    /// <para>
    /// A reCAPTCHA response is a few hundred bytes for a v2 checkbox key and one to two kilobytes
    /// for the longest v3 ones, so this is roughly four times the largest real value. It exists
    /// because the endpoint is anonymous and the field is forwarded upstream: without a cap, one
    /// unauthenticated request can make this service URL-encode a multi-megabyte string and POST it
    /// to the provider, which is amplification we pay for both ways. Nothing legitimate comes
    /// anywhere near the limit, so refusing above it costs no real caller anything.
    /// </para>
    /// </summary>
    private const int MaxAnswerLength = 8192;

    /// <summary>
    /// The longest target. RFC 5321 caps an email address at 254 characters and no phone number is
    /// close, so this is a generous ceiling whose only job is to stop an unbounded string arriving
    /// on an anonymous endpoint.
    /// </summary>
    private const int MaxTargetLength = 320;

    /// <summary>
    /// Presence, size and vocabulary, and deliberately not the target's format.
    /// <para>
    /// The send-code path validates the phone or email shape itself, so a token minted for a
    /// malformed target is bound to a string that path will reject before it ever redeems - the
    /// check would refuse a request that is already harmless. What is checked is what the binding
    /// depends on: a blank target would bind every caller's token to one shared subject, and an
    /// unknown target type means the two endpoints are not talking about the same thing.
    /// </para>
    /// <para>
    /// The two length caps are 400 and not 413. 413 describes a request entity that is too large
    /// for the endpoint, which is Kestrel's own limit and Kestrel's own answer; these are two
    /// oversized fields inside a request whose size was perfectly acceptable, and the caller's fix
    /// is to send a real provider token rather than a smaller request.
    /// </para>
    /// </summary>
    private static void Validate(CaptchaVerifyRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Answer))
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest,
                "The verification challenge response is required.");
        }

        if (request.Answer.Length > MaxAnswerLength)
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest,
                $"The verification challenge response must be at most {MaxAnswerLength} characters.");
        }

        if (string.IsNullOrWhiteSpace(request.Target))
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest,
                "A target phone number or email address is required.");
        }

        if (request.Target.Length > MaxTargetLength)
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest,
                $"The target must be at most {MaxTargetLength} characters.");
        }

        if (!VerificationTargetTypes.IsKnown(request.TargetType))
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest,
                $"The target type must be '{VerificationTargetTypes.Email}' or '{VerificationTargetTypes.Phone}'.");
        }
    }

    /// <summary>The port's signals are nullable so that "unknown" is distinguishable from "empty";
    /// an empty header is unknown, not a signal that the caller has a blank user agent.</summary>
    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
