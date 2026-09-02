namespace UserSvc.Application.Features.Verification;

/// <summary>Ask for a verification code to be sent.</summary>
public sealed record SendVerificationCodeRequest
{
    /// <summary>The phone number or email address to send to.</summary>
    public string Target { get; init; } = string.Empty;

    /// <summary>See <see cref="VerificationTargetTypes"/>.</summary>
    public string TargetType { get; init; } = string.Empty;

    /// <summary>See <c>VerificationPurposes</c>. It scopes the code and the ticket minted from it.</summary>
    public string Purpose { get; init; } = string.Empty;

    /// <summary>
    /// A one-time token from the captcha endpoint. Optional, and only needed after a
    /// <c>CAPTCHA_REQUIRED</c> refusal: it bypasses throttling, but only if it validates for this
    /// same target and device.
    /// </summary>
    public string CaptchaToken { get; init; } = string.Empty;
}

/// <summary>
/// The send was accepted. It deliberately says nothing about whether the target exists, whether
/// delivery succeeded, or what the code is.
/// </summary>
public sealed record SendVerificationCodeResponse
{
    public required string Message { get; init; }

    /// <summary>When the code stops working, so the client can show a countdown instead of guessing.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>Exchange a code for a verification ticket.</summary>
public sealed record VerifyCodeRequest
{
    public string Target { get; init; } = string.Empty;

    public string Code { get; init; } = string.Empty;

    /// <summary>Must match the purpose the code was sent for; a ticket is only ever valid for its
    /// own flow.</summary>
    public string Purpose { get; init; } = string.Empty;
}

/// <summary>The code was correct, and here is the ticket that proves it.</summary>
public sealed record VerifyCodeResponse
{
    /// <summary>Always true - a failed verify is an error response, not a <c>false</c> here.</summary>
    public bool Verified { get; init; } = true;

    /// <summary>
    /// The plaintext ticket, the only time it exists anywhere. Only its hash is stored, so this
    /// value cannot be recovered if the client loses it - it must ask for a new code.
    /// </summary>
    public required string VerificationTicket { get; init; }
}

/// <summary>
/// The per-request facts the send path needs that are not part of the payload. Passed explicitly
/// rather than read from an ambient context, so the application layer stays testable without a
/// request in flight.
/// </summary>
/// <param name="ClientIp">Who to charge the per-IP send budget to. Empty when the server could not
/// determine the peer address; the send path then charges one named shared bucket rather than
/// passing a blank subject to a limiter that refuses one - those callers are throttled together,
/// which is the safe direction.</param>
/// <param name="DeviceId">The <c>X-Device-ID</c> header, or empty. Client-reported and forgeable:
/// it feeds risk-control counting, never an authorization decision.</param>
public sealed record VerificationRequestContext(string ClientIp, string DeviceId);

/// <summary>
/// What kind of address the target is. Lowercase on the wire because that is the public contract;
/// the identity table's own <c>IdentityTypes</c> are uppercase and are a different vocabulary.
/// </summary>
public static class VerificationTargetTypes
{
    public const string Email = "email";
    public const string Phone = "phone";

    public static bool IsKnown(string? targetType) => targetType is Email or Phone;
}
