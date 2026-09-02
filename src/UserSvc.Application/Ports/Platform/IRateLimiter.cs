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
/// reasoning and the cost. That holds for all three operations, in the two shapes a failure can
/// take: a lost read or count allows the request, and a lost reset leaves a counter standing.
/// </para>
/// <para>
/// <b>Three operations, because "5 per minute" and "locked out after 5 failures" are not the same
/// thing.</b> Counting every attempt makes the budget a budget for arriving at all, so somebody who
/// types their password correctly spends it; counting only failures and clearing them on success
/// makes it a lockout, which is what a sign-in door wants. That needs a gate which does not count
/// (<see cref="PeekAsync"/>) and a way to clear (<see cref="ResetAsync"/>) beside the counting one.
/// A caller that genuinely means attempts - because each attempt costs an upstream call, say - uses
/// <see cref="TryAcquireAsync"/> alone, exactly as before.
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
    /// identifier locked out?" asked on every login attempt - want <see cref="PeekAsync"/>, which
    /// answers the same question and counts nothing.
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
    /// <para>
    /// The one caller entitled to ignore that is one using this method as a <i>tally</i> rather
    /// than as a gate: recording a failure that has already happened, having gated on
    /// <see cref="PeekAsync"/> first. Every window has to see that failure or the wider one never
    /// fills, and nothing is being refused on the strength of the return value, so no budget is
    /// spent on an unserved request. Such a caller discards the decision, which is the signal to a
    /// reader that it is a tally and not a gate.
    /// </para>
    /// </param>
    /// <param name="cancellationToken">Honoured before the call is issued; the command itself is not cancellable.</param>
    Task<RateLimitDecision> TryAcquireAsync(
        string dimension,
        string key,
        RateLimitPolicy policy,
        CancellationToken cancellationToken);

    /// <summary>
    /// Answers what <see cref="TryAcquireAsync"/> <i>would</i> answer, and counts nothing.
    /// <para>
    /// This is the operation "is this identifier locked out?" needs. Asked through
    /// <see cref="TryAcquireAsync"/> the question is self-fulfilling: the asking spends the budget,
    /// so an attempt ends up refused for having been made rather than for having failed, and no
    /// configuration value says so.
    /// </para>
    /// <para>
    /// <b>It reports on the request that would come next, not on the count as it stands.</b> A
    /// limit of 5 with five failures already recorded answers <see cref="RateLimitDecision.Allowed"/>
    /// false, because the sixth is what is being asked about. Reporting on the stored count would
    /// make "5 per minute" mean six, and that off-by-one would live in every caller instead of in
    /// <see cref="RateLimitDecision.Peek"/>.
    /// </para>
    /// <para>
    /// <b>It is a read, so it is racy, and that is acceptable here.</b> Two attempts arriving
    /// together both see the same count and both proceed; the counter is still right afterwards
    /// because the failures are counted separately. The cost of the race is one extra attempt
    /// against a locked-out subject, not an unbounded number of them.
    /// </para>
    /// </summary>
    Task<RateLimitDecision> PeekAsync(
        string dimension,
        string key,
        RateLimitPolicy policy,
        CancellationToken cancellationToken);

    /// <summary>
    /// Forgets everything counted against <paramref name="key"/> in <paramref name="dimension"/>,
    /// for each window in <paramref name="policies"/>.
    /// <para>
    /// <b>Why this belongs on the port now, when the argument used to run the other way.</b> The
    /// risk-control adapter already clears the limiter's counters after a solved CAPTCHA, and does
    /// it by deleting the limiter's own keys - with a comment saying that adding a reset to the
    /// port "for this single caller would put a 'clear the evidence' method on every rate limit in
    /// the service". That was right while there was one caller. There are now three: both
    /// back-office sign-in doors clear a mailbox's and an employee number's failures on a
    /// successful sign-in, which the specification states as a step of each flow. A private
    /// key-layout dependency that three call sites reach around the port to reproduce is worse than
    /// a named operation on it.
    /// </para>
    /// <para>
    /// <b>Every window has to be listed.</b> A window is part of a counter's identity, so clearing
    /// the minute of a minute-and-hour pair leaves the hour standing - and the symptom is a lockout
    /// that survives a correct password for up to an hour while the minute counter is visibly
    /// empty.
    /// </para>
    /// <para>
    /// <b>What a lost reset means, and why it is still the fail-open family.</b> The counters stay
    /// as they are, so a subject that has just authenticated correctly keeps its accumulated
    /// failures until the windows expire and can be refused for the rest of them. That is a
    /// nuisance, bounded by the window, and it errs towards refusing - the opposite direction from
    /// a lost count, which errs towards allowing. What it must never do is fail the operation that
    /// asked for it: by then the caller is signed in, and turning a bookkeeping write into a 502
    /// would fail a request that had already succeeded. Adapters therefore swallow and log, and
    /// there is deliberately nothing here for a caller to branch on. The one exception is the
    /// caller's own <paramref name="cancellationToken"/>, which propagates from this operation
    /// exactly as it does from the other two: a client that has gone away is not a failed reset.
    /// </para>
    /// </summary>
    Task ResetAsync(
        string dimension,
        string key,
        IReadOnlyList<RateLimitPolicy> policies,
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
/// The outcome of one <see cref="IRateLimiter.TryAcquireAsync"/> or
/// <see cref="IRateLimiter.PeekAsync"/> call.
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
    /// The same arithmetic for a counter that has <b>not</b> been incremented -
    /// <see cref="IRateLimiter.PeekAsync"/>'s reply.
    /// <para>
    /// The stored count is advanced by one before <see cref="From"/> sees it, because a peek is
    /// asked in order to decide whether to serve something: "the stored count is within the limit"
    /// is a different sentence and a useless one, under which a limit of 5 serves a sixth request.
    /// Putting that increment here rather than in each adapter and each caller is what keeps one
    /// definition of what a limit of 5 means.
    /// </para>
    /// </summary>
    /// <param name="count">The counter's stored value; 0 when nothing has been counted yet.</param>
    /// <param name="policy">The policy the count was taken under.</param>
    /// <param name="timeToLive">Time left on the current window, as the store reports it.</param>
    public static RateLimitDecision Peek(long count, RateLimitPolicy policy, TimeSpan timeToLive) =>
        From(count + 1, policy, timeToLive);

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
