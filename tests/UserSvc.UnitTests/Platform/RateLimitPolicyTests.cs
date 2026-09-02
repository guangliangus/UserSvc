using Shouldly;
using UserSvc.Application.Ports.Platform;
using Xunit;

namespace UserSvc.UnitTests.Platform;

/// <summary>
/// The policy validates in its constructor, so these cases are the difference between a bad limit
/// failing where it was written and one silently letting everything through in production.
/// </summary>
public sealed class RateLimitPolicyTests
{
    [Fact]
    public void FactoriesProduceTheWindowTheirNameClaims()
    {
        RateLimitPolicy.PerMinute(20).Window.ShouldBe(TimeSpan.FromMinutes(1));
        RateLimitPolicy.PerHour(200).Window.ShouldBe(TimeSpan.FromHours(1));
        RateLimitPolicy.PerHour(200).Limit.ShouldBe(200);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ALimitBelowOneIsRejected(int limit) =>
        Should.Throw<ArgumentOutOfRangeException>(() => new RateLimitPolicy(TimeSpan.FromMinutes(1), limit));

    [Fact]
    public void AWindowShorterThanASecondIsRejected() =>
        Should.Throw<ArgumentOutOfRangeException>(() => new RateLimitPolicy(TimeSpan.FromMilliseconds(500), 5));

    /// <summary>
    /// Sub-second precision is refused because the window is rendered in whole seconds inside the
    /// counter key: 60s and 60.5s would share one counter, and whichever policy wrote the TTL last
    /// would decide when both reset.
    /// </summary>
    [Fact]
    public void AWindowWithFractionalSecondsIsRejected() =>
        Should.Throw<ArgumentOutOfRangeException>(() => new RateLimitPolicy(TimeSpan.FromMilliseconds(60_500), 5));
}
