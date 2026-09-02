using System.ComponentModel.DataAnnotations;

namespace UserSvc.Application.Features.RiskControl;

/// <summary>
/// The adaptive send-code throttle's thresholds and lifetimes. Validated at startup, because every
/// value here is part of a security control and a nonsensical one is far cheaper to find at boot
/// than in production.
/// <para>
/// <b>Nothing in this section is a secret and nothing in it is <see cref="RequiredAttribute"/>.</b>
/// The risk engine works with no configuration at all - the defaults below are the Go service's
/// defaults - and it works with no CAPTCHA provider configured either. What a missing provider
/// changes is the escalation, not whether the engine runs; see
/// <see cref="SendCodeThreshold"/> and the adapter's own remarks.
/// </para>
/// </summary>
public sealed class RiskControlOptions : IValidatableObject
{
    public const string SectionName = "RiskControl";

    /// <summary>
    /// Sends allowed on one target (or one device) inside <see cref="SendCodeWindow"/> before the
    /// request being decided is escalated.
    /// <para>
    /// <b>The threshold includes the request being counted</b>, so 5 serves four sends and
    /// challenges the fifth - the convention <c>IRiskControlService</c> fixes, and deliberately not
    /// the one <c>IRateLimiter</c> uses. The floor is 2 rather than 1 because a threshold of 1
    /// would challenge the very first send anybody ever makes, which is not throttling, it is an
    /// outage with a CAPTCHA on it.
    /// </para>
    /// </summary>
    [Range(2, 10_000)]
    public int SendCodeThreshold { get; init; } = 5;

    /// <summary>
    /// The counting window. Whole seconds only - it becomes a <c>RateLimitPolicy</c> window, and
    /// that type refuses a fractional one because the window is part of the counter's identity in
    /// Redis.
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:01", "01:00:00")]
    public TimeSpan SendCodeWindow { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// How long a cooled-down target or device stays refused. It is also the window the CAPTCHA
    /// failure counter rolls over, so consecutive failures mean "inside one cooldown's worth of
    /// time" rather than "ever".
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:01", "12:00:00")]
    public TimeSpan CooldownDuration { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How long "this target has already solved a CAPTCHA" is remembered. It is the second-trigger
    /// window: tripping the threshold again while this marker is alive escalates to a cooldown
    /// instead of asking for another CAPTCHA, because a second CAPTCHA from a subject that just
    /// solved one is not evidence of anything.
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:01", "12:00:00")]
    public TimeSpan CaptchaPassedTtl { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Lifetime of the one-time CAPTCHA token, and the <c>expiresIn</c> the verify endpoint
    /// returns. Short on purpose: it is a bypass credential, and its only legitimate use is the
    /// send-code request the client makes immediately afterwards.
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:10", "01:00:00")]
    public TimeSpan CaptchaTokenTtl { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Consecutive failed CAPTCHA assessments <b>from one device</b> inside
    /// <see cref="CooldownDuration"/>, before that device is cooled down instead of being told to
    /// try the CAPTCHA again. <b>0 switches the escalation off.</b>
    /// <para>
    /// It exists because reCAPTCHA v3 is score-only: a human the model dislikes has no puzzle to
    /// solve their way out of, so without this they loop on <c>CAPTCHA_INVALID</c> forever. A
    /// cooldown at least tells them something true - come back later.
    /// </para>
    /// <para>
    /// <b>Per device and never per target</b>, because a failed assessment consumes nothing
    /// belonging to the address the caller typed; counting it there would let five cheap requests
    /// lock any known phone number out of receiving codes. A caller that sends no device id is
    /// therefore never escalated - it keeps getting a retryable <c>CAPTCHA_INVALID</c>.
    /// </para>
    /// </summary>
    [Range(0, 10_000)]
    public int CaptchaFailThreshold { get; init; } = 5;

    /// <summary>
    /// Which CAPTCHA region this deployment belongs to: <c>overseas</c> or <c>cn</c>. It is the
    /// source of truth for provider selection; the request's <c>X-Language</c> only decides when
    /// this is left unset. One provider is implemented today, so the value is carried through and
    /// logged rather than acted on - it is here so that adding a second provider is a registration,
    /// not a redesign.
    /// </summary>
    public string AppRegion { get; init; } = CaptchaRegions.Overseas;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        // Both of these become RateLimitPolicy windows. That type rejects a fractional second at
        // the call site, which would surface as a 500 from the send-code path rather than as a
        // configuration error - so the same rule is enforced here, at boot, where it names the key.
        foreach (var result in RequireWholeSeconds(SendCodeWindow, nameof(SendCodeWindow)))
        {
            yield return result;
        }

        foreach (var result in RequireWholeSeconds(CooldownDuration, nameof(CooldownDuration)))
        {
            yield return result;
        }

        // 1 would cool a subject down on its first failed CAPTCHA, which is indistinguishable from
        // the endpoint being broken. 0 is the documented off switch and stays legal.
        if (CaptchaFailThreshold == 1)
        {
            yield return new ValidationResult(
                $"{SectionName}:{nameof(CaptchaFailThreshold)} must be 0 (escalation off) or at least 2. "
                + "A threshold of 1 cools the subject down on its first failed assessment, which no "
                + "legitimate user can distinguish from a broken CAPTCHA.",
                [nameof(CaptchaFailThreshold)]);
        }

        if (!CaptchaRegions.IsKnown(AppRegion))
        {
            yield return new ValidationResult(
                $"{SectionName}:{nameof(AppRegion)} must be '{CaptchaRegions.Overseas}' or '{CaptchaRegions.Cn}'.",
                [nameof(AppRegion)]);
        }
    }

    private static IEnumerable<ValidationResult> RequireWholeSeconds(TimeSpan value, string name)
    {
        if (value.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            yield return new ValidationResult(
                $"{SectionName}:{name} must be a whole number of seconds; it is part of a Redis "
                + "counter's identity and is rendered there in seconds.",
                [name]);
        }
    }
}
