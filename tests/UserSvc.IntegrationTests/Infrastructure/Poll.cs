namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>
/// Waits for a condition instead of sleeping for a guess.
/// <para>
/// Every test that drives a real runner has to wait for something a background loop will do on a
/// real poll interval against a real database. A fixed <c>Task.Delay</c> long enough to be reliable
/// on a loaded CI machine is far longer than the thing usually takes, and every one of them is
/// added to the suite's runtime whether it was needed or not; a short one is a flake. Polling costs
/// the actual latency and fails only when the thing genuinely did not happen.
/// </para>
/// </summary>
internal static class Poll
{
    /// <summary>How often the condition is re-checked. Short enough that the wait is close to the
    /// real latency, long enough not to spin.</summary>
    private static readonly TimeSpan Interval = TimeSpan.FromMilliseconds(20);

    /// <summary>Waits until <paramref name="condition"/> holds.</summary>
    /// <param name="condition">The thing being waited for. Called on the test's thread, so it must
    /// not block.</param>
    /// <param name="timeout">How long to wait before giving up.</param>
    /// <returns>True when the condition held, false on timeout.</returns>
    public static async Task<bool> UntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(condition);

        var deadline = DateTimeOffset.UtcNow + timeout;

        while (true)
        {
            if (condition())
            {
                return true;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                return false;
            }

            await Task.Delay(Interval);
        }
    }

    /// <summary>Waits until an asynchronous <paramref name="condition"/> - a query, in practice -
    /// holds.</summary>
    /// <param name="condition">The thing being waited for.</param>
    /// <param name="timeout">How long to wait before giving up.</param>
    /// <returns>True when the condition held, false on timeout.</returns>
    public static async Task<bool> UntilAsync(Func<Task<bool>> condition, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(condition);

        var deadline = DateTimeOffset.UtcNow + timeout;

        while (true)
        {
            if (await condition())
            {
                return true;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                return false;
            }

            await Task.Delay(Interval);
        }
    }
}
