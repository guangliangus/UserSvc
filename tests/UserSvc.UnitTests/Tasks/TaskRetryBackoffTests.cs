using Shouldly;
using UserSvc.Application.Tasks;
using Xunit;

namespace UserSvc.UnitTests.Tasks;

/// <summary>
/// The retry delay a handler re-arms with. Every assertion is a range, because the jitter is the
/// function's whole reason for existing: a fixed answer would mean every task that failed together
/// retries together.
/// </summary>
public sealed class TaskRetryBackoffTests
{
    private static readonly TimeSpan Base = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan Cap = TimeSpan.FromMinutes(30);

    [Theory]
    [InlineData(1, 30)]
    [InlineData(2, 60)]
    [InlineData(3, 120)]
    [InlineData(4, 240)]
    [InlineData(5, 480)]
    [InlineData(6, 960)]
    public void TheDelayDoublesPerAttemptWithinItsJitterWindow(int attempt, int expectedSeconds)
    {
        var nominal = TimeSpan.FromSeconds(expectedSeconds);

        var delay = TaskRetryBackoff.Delay(attempt, Base, Cap);

        delay.ShouldBeGreaterThanOrEqualTo(nominal, "The jitter is added, never subtracted.");
        delay.ShouldBeLessThan(nominal + (nominal / 5), "The jitter window is 0-20%.");
    }

    [Fact]
    public void TheCapHoldsAgainstAnAttemptCountThatHasRunAway()
    {
        // int.MaxValue is not a realistic attempt number; it is the one that proves the saturation
        // is tested before the doubling. Doubling first and clamping second overflows Ticks and
        // wraps negative, which would turn a saturated backoff into an immediate retry.
        foreach (var attempt in new[] { 7, 20, 100, int.MaxValue })
        {
            var delay = TaskRetryBackoff.Delay(attempt, Base, Cap);

            delay.ShouldBeGreaterThanOrEqualTo(Cap, $"attempt {attempt}");
            delay.ShouldBeLessThan(Cap + (Cap / 5), $"attempt {attempt}");
        }
    }

    /// <summary>
    /// A cap the doubling cannot reach is the case that separates "test the cap before doubling"
    /// from "double and then clamp", and it is the only case that does: with any reachable cap the
    /// two spellings agree exactly (measured - a mutation swapping them passes every other test
    /// here). With an unreachable one, doubling first walks Ticks past <see cref="long.MaxValue"/>
    /// and wraps NEGATIVE, so the saturated backoff becomes an immediate retry - the exact opposite
    /// of what a cap is for.
    /// </summary>
    [Fact]
    public void TheCapHoldsEvenWhenTheDoublingCannotReachIt()
    {
        foreach (var attempt in new[] { 30, 100, int.MaxValue })
        {
            var delay = TaskRetryBackoff.Delay(attempt, Base, TimeSpan.MaxValue);

            delay.ShouldBeGreaterThan(Base, $"attempt {attempt}");
        }
    }

    [Fact]
    public void ANonPositiveAttemptIsReadAsTheFirst()
    {
        foreach (var attempt in new[] { 0, -1, -100 })
        {
            var delay = TaskRetryBackoff.Delay(attempt, Base, Cap);

            delay.ShouldBeGreaterThanOrEqualTo(Base, $"attempt {attempt}");
            delay.ShouldBeLessThan(Base + (Base / 5), $"attempt {attempt}");
        }
    }

    [Fact]
    public void MissingBoundsFallBackToTheShippedDefaults()
    {
        var first = TaskRetryBackoff.Delay(1, TimeSpan.Zero, TimeSpan.Zero);
        var saturated = TaskRetryBackoff.Delay(50, TimeSpan.Zero, TimeSpan.Zero);

        first.ShouldBeGreaterThanOrEqualTo(TimeSpan.FromSeconds(30));
        first.ShouldBeLessThan(TimeSpan.FromSeconds(36));
        saturated.ShouldBeGreaterThanOrEqualTo(TimeSpan.FromMinutes(30));
        saturated.ShouldBeLessThan(TimeSpan.FromMinutes(36));
    }

    [Fact]
    public void TheJitterActuallySpreadsRetriesApart()
    {
        // The property that matters and the one an implementation loses by accident: a thousand
        // tasks re-armed in the same instant must not be re-armed to the same instant.
        var delays = Enumerable.Range(0, 1000)
            .Select(_ => TaskRetryBackoff.Delay(3, Base, Cap))
            .Distinct()
            .Count();

        delays.ShouldBeGreaterThan(
            900, "Without jitter this is 1, and the recovery attempt is itself a thundering herd.");
    }
}
