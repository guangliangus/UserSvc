namespace UserSvc.Application.Ports.Platform;

/// <summary>
/// Fixed-window request counting on shared state. Every instance of the service counts into the
/// same bucket, which is the whole reason this crosses a process boundary and therefore the whole
/// reason it is a port: an in-process counter would give an attacker N times the budget for N pods.
/// <para>
/// The port returns a <see cref="RateLimitDecision"/> rather than a <see cref="bool"/> on purpose.
/// A 429 without <c>Retry-After</c> tells a client nothing it can act on, so it retries
/// immediately and spends the rest of the window being refused; the header is the only thing that
/// turns a refusal into a wait. <see cref="RateLimitDecision.RetryAfter"/> is what feeds it, and
/// <c>RateLimitedException</c> already carries that field through to the response.
/// </para>
/// <para>
/// <b>Implementations must fail open.</b> See <see cref="RateLimitDecision.FailOpen"/> for the
/// reasoning and the cost.
/// </para>
/// </summary>
public interface IRateLimiter
{
    /// <summary>
    /// Counts one request against <paramref name="key"/> in <paramref name="dimension"/> and
    /// reports whether it is allowed.
    /// <para>
    /// The call is <b>not</b> free of side effects: it increments the counter whether or not the
    /// request ultimately succeeds. Callers that must not spend budget on a read - "is this
    /// identifier locked out?" asked on every login attempt - need a separate read-only check, not
    /// this method.
    /// </para>
    /// </summary>
    /// <param name="dimension">
    /// What is being limited, as a stable slug: <c>login-ip</c>, <c>send-code-target</c>,
    /// <c>otp-staff</c>. Two dimensions never share a counter, so a per-IP login limit and a
    /// per-IP password-reset limit are independent budgets.
    /// </param>
    /// <param name="key">
    /// The subject inside that dimension - an IP address, a phone number, a staff id. Free-form:
    /// the adapter is responsible for turning it into a safe key.
    /// </param>
    /// <param name="policy">
    /// Window and limit. Different windows on the same subject are different counters.
    /// <para>
    /// A caller enforcing several policies on one subject - the usual pair is 20/minute and
    /// 200/hour - must <b>stop at the first refusal</b> and not evaluate the rest. Each call spends
    /// a unit of its own budget, so carrying on past a refused minute window charges the hour
    /// window for a request that was never served; a client retrying into a one-minute block then
    /// exhausts its hourly allowance on requests it never received an answer to, and a short
    /// throttle silently becomes an hour-long one.
    /// </para>
    /// </param>
    /// <param name="cancellationToken">Honoured before the call is issued; the command itself is not cancellable.</param>
    Task<RateLimitDecision> TryAcquireAsync(
        string dimension,
        string key,
        RateLimitPolicy policy,
        CancellationToken cancellationToken);
}

/// <summary>
/// How many requests a subject may make per window. Immutable and validated on construction, so a
/// nonsensical policy fails at the call site that built it rather than silently letting everything
/// through at run time.
/// </summary>
public sealed record RateLimitPolicy
{
    public RateLimitPolicy(TimeSpan window, int limit)
    {
        if (window < TimeSpan.FromSeconds(1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(window),
                window,
                "A rate-limit window must be at least one second.");
        }

        // Whole seconds, because the window is part of the counter's identity in the store and is
        // rendered there in seconds. Allowing 60.5s would let two policies that are meant to be
        // different share one counter - and the one that wrote the TTL last would decide when both
        // reset.
        if (window.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(window),
                window,
                "A rate-limit window must be a whole number of seconds.");
        }

        if (limit < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(limit),
                limit,
                "A rate-limit limit must be at least one request per window.");
        }

        Window = window;
        Limit = limit;
    }

    /// <summary>Length of the fixed window.</summary>
    public TimeSpan Window { get; }

    /// <summary>Requests allowed inside one window. The <c>Limit</c>-th request is still served.</summary>
    public int Limit { get; }

    public static RateLimitPolicy PerMinute(int limit) => new(TimeSpan.FromMinutes(1), limit);

    public static RateLimitPolicy PerHour(int limit) => new(TimeSpan.FromHours(1), limit);
}

/// <summary>
/// The outcome of one <see cref="IRateLimiter.TryAcquireAsync"/> call.
/// </summary>
/// <param name="Allowed">Whether the caller may proceed.</param>
/// <param name="Remaining">
/// Requests left in this window after the current one, never negative. Suitable for an
/// <c>X-RateLimit-Remaining</c> header.
/// </param>
/// <param name="RetryAfter">
/// How long until the window resets. <see cref="TimeSpan.Zero"/> when
/// <paramref name="Allowed"/> is true - there is nothing to wait for.
/// </param>
public sealed record RateLimitDecision(bool Allowed, int Remaining, TimeSpan RetryAfter)
{
    /// <summary>
    /// Turns a raw window count into a decision. This is the port's arithmetic contract, not a
    /// convenience: it fixes the two things every caller and every adapter must agree on.
    /// <list type="number">
    /// <item>
    /// <b>The comparison is strictly greater-than.</b> A limit of 5 serves five requests and
    /// refuses the sixth. Counting the request that reaches the limit as a violation would make
    /// "5 per minute" mean four, and no configuration value would say so.
    /// </item>
    /// <item>
    /// <b><paramref name="timeToLive"/> comes from the store, not from the clock.</b> A caller
    /// three seconds into a one-minute window is told to come back in 57 seconds, not 60. Telling
    /// it 60 would be harmless; telling it the window length while the counter is about to expire
    /// wastes the client's next attempt.
    /// </item>
    /// </list>
    /// </summary>
    /// <param name="count">The counter's value after this request was counted, so it starts at 1.</param>
    /// <param name="policy">The policy the count was taken under.</param>
    /// <param name="timeToLive">
    /// Time left on the current window. Non-positive values (no TTL observed) fall back to the
    /// full window - the honest over-estimate.
    /// </param>
    public static RateLimitDecision From(long count, RateLimitPolicy policy, TimeSpan timeToLive)
    {
        ArgumentNullException.ThrowIfNull(policy);

        var remaining = (int)Math.Clamp(policy.Limit - count, 0, policy.Limit);
        var allowed = count <= policy.Limit;

        return allowed
            ? new RateLimitDecision(true, remaining, TimeSpan.Zero)
            : new RateLimitDecision(false, 0, timeToLive > TimeSpan.Zero ? timeToLive : policy.Window);
    }

    /// <summary>
    /// What an adapter returns when the store is unreachable: allow, and do not pretend to know
    /// how much budget is left.
    /// <para>
    /// A rate limiter is a protective measure layered on top of endpoints that are already
    /// authenticated, validated and audited. If Redis is down, refusing every request converts a
    /// Redis outage into a full outage of login, sign-up and verification codes - the limiter would
    /// cause exactly the incident it exists to prevent. This is the same reasoning as the
    /// revocation set's read path in the failure-semantics table (docs/architecture.md), and the
    /// opposite of its write path: a lost revocation write leaves a signed-out device working with
    /// no other backstop, whereas a lost increment merely lets one more request through a limit
    /// that only ever shaved load.
    /// </para>
    /// <para>
    /// The accepted cost is real and worth stating: while Redis is down the service is unthrottled,
    /// so brute force is bounded only by whatever else stands in front of it. That is why the
    /// adapter logs a warning per affected request - the rate of those lines is the signal that
    /// this window is open.
    /// </para>
    /// </summary>
    public static RateLimitDecision FailOpen(RateLimitPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        // Remaining is the full limit rather than limit - 1: nothing was counted, so nothing was
        // spent. Reporting a decrement would be inventing a number the store never produced.
        return new RateLimitDecision(true, policy.Limit, TimeSpan.Zero);
    }
}
