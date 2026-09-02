using Shouldly;
using UserSvc.Application.Features.BackOffice.Tenants;
using Xunit;

namespace UserSvc.UnitTests.Tenancy;

/// <summary>The generated password has to satisfy the same policy a person's own choice does, and
/// has to survive being read off a screen and typed by hand.</summary>
public sealed class InitialPasswordGeneratorTests
{
    [Fact]
    public void EveryPasswordCarriesAllThreeCharacterClasses()
    {
        for (var i = 0; i < 200; i++)
        {
            var password = InitialPasswordGenerator.Generate();

            password.Length.ShouldBe(10);
            password.Any(char.IsUpper).ShouldBeTrue();
            password.Any(char.IsLower).ShouldBeTrue();
            password.Any(char.IsAsciiDigit).ShouldBeTrue();
        }
    }

    [Fact]
    public void LookAlikeGlyphsAreLeftOut()
    {
        // A zero that turns out to be an O costs a support ticket.
        for (var i = 0; i < 200; i++)
        {
            InitialPasswordGenerator.Generate()
                .Any(c => c is '0' or 'O' or '1' or 'l' or 'I')
                .ShouldBeFalse();
        }
    }

    [Fact]
    public void TheGuaranteedCharactersDoNotAlwaysLandInTheSamePlaces()
    {
        // Without the final shuffle the first three positions would be upper, lower, digit every
        // time, which quietly removes most of the entropy an attacker has to guess.
        var firstPositions = Enumerable.Range(0, 200)
            .Select(_ => InitialPasswordGenerator.Generate()[0])
            .ToList();

        firstPositions.Any(char.IsLower).ShouldBeTrue();
        firstPositions.Any(char.IsAsciiDigit).ShouldBeTrue();
    }
}
