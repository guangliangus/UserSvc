namespace UserSvc.Application.Tasks;

/// <summary>
/// The retry delay a task handler re-arms a failed task with: exponential, capped, and jittered.
/// <para>
/// It lives here, in the inner ring, because the caller is a handler
/// (<see cref="Ports.Platform.ITaskHandler"/>) rather than the runner - the runner never re-arms
/// anything, by the ownership rule on that interface. It is a pure function of its arguments so a
/// handler can unit-test its own retry policy without a queue, a clock or a database.
/// </para>
/// <para>
/// <b>It returns a delay, never an instant.</b> <see cref="Ports.Platform.ITaskQueue.ReArmAsync"/>
/// turns it into <c>deliver_on = now() + delay</c> evaluated by PostgreSQL, so the window is
/// measured entirely on the clock that will later decide whether it has passed. Computing a target
/// time here from the process clock instead would make every backoff wrong by whatever this pod's
/// clock and the database's disagree about, and the symptom - a retry that fires early or late -
/// reads as a tuning problem rather than as skew.
/// </para>
/// </summary>
public static class TaskRetryBackoff
{
    /// <summary>The base delay used when the caller supplies none. The Go service's default.</summary>
    private static readonly TimeSpan DefaultBase = TimeSpan.FromSeconds(30);

    /// <summary>The ceiling used when the caller supplies none. The Go service's default.</summary>
    private static readonly TimeSpan DefaultCap = TimeSpan.FromMinutes(30);

    /// <summary>
    /// The delay before attempt <paramref name="attempt"/> + 1:
    /// <c>min(base * 2^(attempt-1), cap)</c> plus up to 20% jitter.
    /// <para>
    /// <b>The jitter is the point of the function, not decoration.</b> Retries are correlated by
    /// construction: whatever broke - a dependency refusing every call, a bulk recompute enqueuing
    /// ten thousand rows at once - broke them all at the same moment, so an un-jittered backoff
    /// re-arms them all to the same second and the recovery attempt is itself a thundering herd
    /// against the thing that just failed. Spreading each retry over a 20% window turns one spike
    /// into a ramp. It is added rather than subtracted so the delay is never shorter than the
    /// nominal backoff.
    /// </para>
    /// </summary>
    /// <param name="attempt">Which attempt has just failed, counting from 1. Zero or negative is
    /// read as 1, so a caller whose counter starts at zero gets the base delay rather than a
    /// negative exponent.</param>
    /// <param name="baseDelay">The first delay. Zero or negative falls back to 30 seconds.</param>
    /// <param name="cap">The ceiling the doubling saturates at, before jitter. Zero or negative
    /// falls back to 30 minutes. A cap is not optional: without one, attempt 20 of a six-attempt
    /// budget that somebody later raised is a delay measured in days.</param>
    /// <returns>How long to hold the task back, in the range <c>[delay, delay * 1.2)</c>.</returns>
    public static TimeSpan Delay(int attempt, TimeSpan baseDelay, TimeSpan cap)
    {
        var ticks = baseDelay <= TimeSpan.Zero ? DefaultBase.Ticks : baseDelay.Ticks;
        var capTicks = cap <= TimeSpan.Zero ? DefaultCap.Ticks : cap.Ticks;

        // A non-positive attempt needs no normalising: the loop runs attempt - 1 times, so 0 and
        // every negative run it not at all and get the base delay - exactly what attempt 1 gets.
        // (Go writes an explicit "if attempt <= 0 { attempt = 1 }" here. Measured by mutating it
        // out: that line changes no answer in either implementation.)
        for (var doubling = 1; doubling < attempt; doubling++)
        {
            // Tested against the cap BEFORE doubling rather than after. Doubling first and
            // clamping second is the obvious spelling and it overflows: this runs up to
            // int.MaxValue times if a caller's attempt counter has run away, and a Ticks value
            // doubled past long.MaxValue wraps NEGATIVE, which would turn a saturated backoff into
            // an immediate retry - the exact opposite of what the cap is for.
            if (ticks >= capTicks / 2)
            {
                ticks = capTicks;
                break;
            }

            ticks *= 2;
        }

        ticks = Math.Min(ticks, capTicks);

        // A fifth of the delay, so the jitter window is 0-20% and the ceiling is positive for any
        // delay of five ticks or more. Below that there is nothing to spread and the bucket would
        // be zero, which NextInt64 rejects.
        var bucket = ticks / 5;
        var jitter = bucket <= 0 ? 0 : Random.Shared.NextInt64(bucket);

        // The addition is clamped for the same reason the doubling is tested before it happens: a
        // cap near TimeSpan.MaxValue leaves no headroom, and ticks + jitter would wrap negative -
        // a "delay" in the past, which re-arms the task for immediate retry forever.
        return TimeSpan.FromTicks(ticks + Math.Min(jitter, long.MaxValue - ticks));
    }
}
