using System.ComponentModel.DataAnnotations;
using Shouldly;
using UserSvc.Application.Features.Verification;
using Xunit;

namespace UserSvc.UnitTests.Features;

/// <summary>
/// The options are bound with <c>ValidateDataAnnotations().ValidateOnStart()</c>, so these
/// attributes are the difference between a misconfiguration that refuses to boot and one that
/// silently issues codes nobody can use.
/// <para>
/// <c>[Range(typeof(TimeSpan), ...)]</c> is worth an explicit test rather than trust: it validates
/// through a type converter, so an unparseable bound would make the attribute pass everything
/// instead of failing loudly - a guard that quietly stops guarding.
/// </para>
/// </summary>
public sealed class VerificationOptionsTests
{
    [Fact]
    public void TheDefaultsAreValid()
    {
        Validate(new VerificationOptions()).ShouldBeEmpty();
    }

    /// <summary>
    /// Zero is the value that matters. The original clamped a non-positive ticket TTL to ten
    /// minutes at run time; here it must refuse to start, because a zero TTL means every ticket
    /// expiring the instant it is issued and no flow completing.
    /// </summary>
    [Fact]
    public void AZeroLifetimeIsRefusedRatherThanClampedAtRunTime()
    {
        var results = Validate(new VerificationOptions
        {
            CodeExpires = TimeSpan.Zero,
            TicketTtl = TimeSpan.Zero,
        });

        results.Count.ShouldBe(2);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ABudgetThatCouldNeverServeARequestIsRefused(int perMinute)
    {
        Validate(new VerificationOptions { SendPerIpPerMinute = perMinute }).ShouldNotBeEmpty();
    }

    private static List<ValidationResult> Validate(VerificationOptions options)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(options, new ValidationContext(options), results, validateAllProperties: true);
        return results;
    }
}
