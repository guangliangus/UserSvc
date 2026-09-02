namespace UserSvc.Application.Ports.External;

/// <summary>
/// Adaptive throttling for the send-code path, plus the CAPTCHA escalation that lets a legitimate
/// user who tripped it prove they are human and carry on.
/// <para>
/// The shape is a three-state decision rather than a limit, because that is what the flow needs:
/// under the threshold the code is sent; over it the first time the client is asked to solve a
/// CAPTCHA; over it a second time - having already solved one - the subject is cooled down, since
/// at that point another CAPTCHA is not evidence of anything.
/// </para>
/// <para>
/// This is a port because the real implementation talks to Redis for the counters and to a CAPTCHA
/// provider (reCAPTCHA Enterprise) over the network. No such provider is configured yet, so the
/// registered adapter is a placeholder - and a placeholder for a security component <b>refuses</b>
/// rather than approves. Concretely, that means it never issues or accepts a CAPTCHA token, which
/// is the only part of this interface that can grant a bypass.
/// </para>
/// </summary>
public interface IRiskControlService
{
    /// <summary>
    /// Decides what happens to one send-code request, counting it in the process.
    /// <para>
    /// Never throws for risk reasons. Every infrastructure failure inside degrades to
    /// <see cref="SendCodeRiskDecision.RiskAction.Allow"/>: the counters exist to slow down abuse
    /// of a code-sending endpoint, and a counting outage must not stop legitimate users from
    /// signing in.
    /// </para>
    /// <para>
    /// <b>Two rules an implementation cannot infer from this signature, both load-bearing:</b>
    /// </para>
    /// <list type="number">
    /// <item>
    /// <b>An existing cooldown is checked before anything is counted</b>, on the target dimension
    /// and then the device dimension. Counting first would let a subject already serving a cooldown
    /// inflate the counter that decides its next one, so hammering during a cooldown would extend
    /// it - a lockout that grows the more the client retries, which is the shape of a bug rather
    /// than of a policy.
    /// </item>
    /// <item>
    /// <b>The threshold comparison includes the request being decided:</b> the count is taken after
    /// the increment and the trip is <c>count &gt;= threshold</c>, so a threshold of 5 serves four
    /// requests and challenges the fifth. This is deliberately <i>not</i> the convention
    /// <c>IRateLimiter</c> uses - a rate limit of 5 serves five - because a threshold is the point
    /// at which suspicion starts, while a limit is an allowance that must be spendable in full.
    /// Two conventions in one codebase is a real cost; getting either one backwards is a silent
    /// off-by-one in a security control, which is worse.
    /// </item>
    /// </list>
    /// </summary>
    Task<SendCodeRiskDecision> EvaluateSendCodeAsync(
        SendCodeRiskContext context,
        CancellationToken cancellationToken);

    /// <summary>
    /// Redeems a one-time CAPTCHA token issued by <see cref="VerifyCaptchaAsync"/> for this exact
    /// target and device, clearing the send-code counters.
    /// <para>
    /// Returns <see langword="false"/> - never throws - when the token is missing, already used,
    /// bound to a different subject, or simply cannot be checked. False means "no bypass": the
    /// alternative is honouring a token nothing has validated.
    /// </para>
    /// <para>
    /// <b>False is an answer to the client, not a reason to try the other door.</b> A send-code
    /// request that presented a token and had it refused answers <c>CAPTCHA_INVALID</c> and stops -
    /// it does not fall through to <see cref="EvaluateSendCodeAsync"/>. Falling through would send
    /// the code anyway whenever the subject happened to be under the threshold, so a client whose
    /// token was rejected would see success and never learn its CAPTCHA is broken, and the response
    /// would stop distinguishing "your proof was bad" from "you did not need proof". Only a request
    /// that presented <i>no</i> token is evaluated by the throttle.
    /// </para>
    /// <para>
    /// <b>The compare and the delete must be one indivisible step</b> - a Lua script or an
    /// equivalent single-round-trip primitive, never a read followed by a delete. A token is a
    /// bypass credential, and with two round trips N concurrent requests all read the same live
    /// token and all get their bypass; the delete afterwards only decides which of them cleaned up.
    /// Whatever follows a successful redemption - clearing the send-code counters, marking the
    /// subject as having passed - is best-effort and happens after, because losing it costs one
    /// extra challenge, whereas redeeming twice costs the gate itself.
    /// </para>
    /// </summary>
    Task<bool> TryConsumeCaptchaTokenAsync(
        string captchaToken,
        SendCodeRiskContext context,
        CancellationToken cancellationToken);

    /// <summary>
    /// Assesses a provider token (the value the client's CAPTCHA SDK produced) and, on success,
    /// issues the one-time token that <see cref="TryConsumeCaptchaTokenAsync"/> will redeem. There
    /// is no server-side challenge state - the provider token is the proof.
    /// <para>
    /// <b>This method must throw rather than return a token it could not justify.</b> A returned
    /// token is a bypass credential; producing one without a completed assessment would mean the
    /// CAPTCHA gate silently stops existing while still appearing to work.
    /// </para>
    /// </summary>
    /// <exception cref="Errors.AppException">
    /// The assessment could not be completed - provider unreachable, unconfigured, or the issued
    /// token could not be stored. Distinct from a token that was assessed and rejected, which is
    /// reported to the caller as a refusal, not as a fault.
    /// </exception>
    Task<CaptchaVerificationResult> VerifyCaptchaAsync(
        CaptchaVerificationContext context,
        CancellationToken cancellationToken);
}

/// <summary>Who is asking for a verification code, in the two dimensions that are counted.</summary>
/// <param name="Target">The phone number or email address the code would go to.</param>
/// <param name="TargetType">Which of the two it is: <c>phone</c> or <c>email</c>.</param>
/// <param name="DeviceId">
/// The client's device identifier, or empty when the request carried none. It is counted
/// separately from the target: an attacker cycling through fresh phone numbers from one device
/// trips the device dimension long before any single target is noticed.
/// </param>
public sealed record SendCodeRiskContext(string Target, string TargetType, string DeviceId);

/// <summary>
/// What to do with a send-code request. Construct it through the factories - they are the only
/// combinations of action, reset time and cooldown that mean anything.
/// </summary>
public sealed record SendCodeRiskDecision
{
    private SendCodeRiskDecision(RiskAction action, DateTimeOffset? resetAt, TimeSpan retryAfter)
    {
        Action = action;
        ResetAt = resetAt;
        RetryAfter = retryAfter;
    }

    /// <summary>
    /// Nested deliberately: <c>Ports/</c> is guarded to interfaces and contract records only, and
    /// an enum is neither. Nesting keeps the decision's vocabulary next to the decision instead of
    /// exiling it to a layer that has no reason to own it.
    /// </summary>
    public enum RiskAction
    {
        /// <summary>Send the code.</summary>
        Allow,

        /// <summary>Ask the client to solve a CAPTCHA and replay the request with the resulting token.</summary>
        CaptchaRequired,

        /// <summary>Refuse until <see cref="SendCodeRiskDecision.ResetAt"/>; a CAPTCHA will not help.</summary>
        Cooldown,
    }

    public RiskAction Action { get; }

    /// <summary>When the cooldown lifts. Null unless <see cref="Action"/> is <see cref="RiskAction.Cooldown"/>.</summary>
    public DateTimeOffset? ResetAt { get; }

    /// <summary>
    /// How long the caller should wait. <see cref="TimeSpan.Zero"/> unless <see cref="Action"/> is
    /// <see cref="RiskAction.Cooldown"/>. Carried as a duration rather than a second count because
    /// the wire format is the API layer's decision, not this one's. Same name as
    /// <c>RateLimitDecision.RetryAfter</c> on purpose - both end up in the same response header.
    /// </summary>
    public TimeSpan RetryAfter { get; }

    public static SendCodeRiskDecision Allow() => new(RiskAction.Allow, null, TimeSpan.Zero);

    public static SendCodeRiskDecision CaptchaRequired() => new(RiskAction.CaptchaRequired, null, TimeSpan.Zero);

    /// <param name="resetAt">Absolute instant the cooldown lifts.</param>
    /// <param name="retryAfter">
    /// Time remaining from now. Passed in rather than derived from <paramref name="resetAt"/>
    /// because the implementation holds the clock and this record must not. Negative input is
    /// clamped to zero: a cooldown that already lapsed is not a negative wait.
    /// </param>
    public static SendCodeRiskDecision Cooldown(DateTimeOffset resetAt, TimeSpan retryAfter) =>
        new(RiskAction.Cooldown, resetAt, retryAfter < TimeSpan.Zero ? TimeSpan.Zero : retryAfter);
}

/// <summary>Everything a provider assessment needs about the request being vouched for.</summary>
/// <param name="ProviderToken">The opaque token the client's CAPTCHA SDK produced.</param>
/// <param name="Target">Same target as the send-code request this will unblock.</param>
/// <param name="TargetType"><c>phone</c> or <c>email</c>.</param>
/// <param name="DeviceId">Device the token will be bound to; empty binds it to "no device".</param>
/// <param name="Region">
/// Which provider to assess with. Deployments in different regions cannot always reach the same
/// CAPTCHA vendor, so the choice is data, not a compile-time constant.
/// </param>
/// <param name="Platform">
/// <c>ios</c>, <c>android</c> or <c>web</c>. Provider site keys are issued per platform, so
/// assessing a mobile token against the web key fails for a reason that looks nothing like the
/// cause.
/// </param>
/// <param name="ClientIpAddress">Caller's IP, passed to the provider as an assessment signal. Null when unknown.</param>
/// <param name="UserAgent">Caller's user agent, same purpose. Null when unknown.</param>
public sealed record CaptchaVerificationContext(
    string ProviderToken,
    string Target,
    string TargetType,
    string DeviceId,
    string Region,
    string Platform,
    string? ClientIpAddress,
    string? UserAgent);

/// <summary>
/// A successful assessment. The token is single-use and bound to the target and device from the
/// request that produced it - replaying it for another target does nothing.
/// </summary>
/// <param name="CaptchaToken">
/// The bypass token, in plaintext. This is the only time it exists in readable form; the store
/// keeps a hash.
/// </param>
/// <param name="ExpiresIn">Lifetime of the token, for the response's <c>expiresIn</c>.</param>
public sealed record CaptchaVerificationResult(string CaptchaToken, TimeSpan ExpiresIn);
