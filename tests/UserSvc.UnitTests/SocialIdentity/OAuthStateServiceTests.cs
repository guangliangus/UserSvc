using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.SocialIdentity;
using Xunit;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// The stateless OAuth state. There is no storage to inspect, so the whole contract is here: a
/// state this server issued verifies, and everything else does not.
/// </summary>
public sealed class OAuthStateServiceTests
{
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 10, 0, 0, TimeSpan.Zero));

    private OAuthStateService Sut => new(
        Options.Create(new SocialIdentityOptions
        {
            SigningKey = new string('a', 64),
            StateLifetime = TimeSpan.FromMinutes(5),
        }),
        _clock);

    [Fact]
    public void AnIssuedStateCarriesTheDeviceIdBack()
    {
        var sut = Sut;

        sut.ReadDeviceId(sut.Issue("device-7")).ShouldBe("device-7");
    }

    /// <summary>A browser redirect has no device header, and web OAuth must still work.</summary>
    [Fact]
    public void AStateIssuedWithoutADeviceIdIsStillValid()
    {
        var sut = Sut;

        sut.ReadDeviceId(sut.Issue(string.Empty)).ShouldBe(string.Empty);
    }

    [Fact]
    public void TheNonceIsStableForOneStateAndDifferentBetweenTwo()
    {
        var sut = Sut;
        var first = sut.Issue("device-1");
        var second = sut.Issue("device-1");

        sut.ReadNonce(first).ShouldBe(sut.ReadNonce(first));
        sut.ReadNonce(first).ShouldNotBe(sut.ReadNonce(second));
        sut.ReadNonce(first).ShouldNotBeEmpty();
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-state")]
    [InlineData("no-dot-separator")]
    [InlineData("...")]
    [InlineData("!!!.???")]
    public void AMalformedStateIsRefused(string state)
    {
        var thrown = Should.Throw<BadRequestException>(() => Sut.ReadDeviceId(state));

        thrown.ErrorCode.ShouldBe(ErrorCodes.InvalidState);
    }

    /// <summary>
    /// The signature is the state's only defence: without this check the payload is a query
    /// parameter anybody can retype.
    /// </summary>
    [Fact]
    public void AStateWhoseSignatureWasTamperedWithIsRefused()
    {
        var sut = Sut;
        var state = sut.Issue("device-1");

        Should.Throw<BadRequestException>(() => sut.ReadDeviceId(state + "x"))
            .ErrorCode.ShouldBe(ErrorCodes.InvalidState);
    }

    [Fact]
    public void AStateWhosePayloadWasTamperedWithIsRefused()
    {
        var sut = Sut;
        var state = sut.Issue("device-1");
        var separator = state.IndexOf('.', StringComparison.Ordinal);

        // Same signature, a payload that no longer matches it.
        var forged = sut.Issue("device-2")[..separator] + state[separator..];

        Should.Throw<BadRequestException>(() => sut.ReadDeviceId(forged));
    }

    [Fact]
    public void AnExpiredStateIsRefused()
    {
        var sut = Sut;
        var state = sut.Issue("device-1");

        _clock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));

        Should.Throw<BadRequestException>(() => sut.ReadDeviceId(state))
            .ErrorCode.ShouldBe(ErrorCodes.InvalidState);
    }

    [Fact]
    public void AStateIsStillValidOneSecondBeforeItExpires()
    {
        var sut = Sut;
        var state = sut.Issue("device-1");

        _clock.Advance(TimeSpan.FromMinutes(5) - TimeSpan.FromSeconds(1));

        sut.ReadDeviceId(state).ShouldBe("device-1");
    }

    /// <summary>
    /// The state and the binding token share a key. Domain separation is what stops one being
    /// presented where the other is expected - which would otherwise let a caller who can obtain a
    /// state manufacture a binding proposal.
    /// </summary>
    [Fact]
    public void ABindingTokenCannotBePresentedAsAState()
    {
        var options = Options.Create(new SocialIdentityOptions { SigningKey = new string('a', 64) });
        var states = new OAuthStateService(options, _clock);
        var tokens = new SocialBindingTokenService(options, _clock);

        var bindingToken = tokens.Issue(new FirebaseBindingProposal("uid", "google.com", "sub", 42, "a***@b.com", "A"));

        Should.Throw<BadRequestException>(() => states.ReadDeviceId(bindingToken));
        Should.Throw<UnauthorizedException>(() => tokens.Open(states.Issue("device-1")));
    }

    [Fact]
    public void ADifferentSigningKeyRefusesAnotherDeploymentsState()
    {
        var mine = Sut;
        var theirs = new OAuthStateService(
            Options.Create(new SocialIdentityOptions { SigningKey = new string('b', 64) }),
            _clock);

        Should.Throw<BadRequestException>(() => mine.ReadDeviceId(theirs.Issue("device-1")));
    }
}
