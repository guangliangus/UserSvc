using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.SocialIdentity;
using Xunit;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// The Firebase binding proposal. It is a bearer credential for "attach this provider account to
/// that existing account", so the tests are about what it refuses.
/// </summary>
public sealed class SocialBindingTokenServiceTests
{
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 10, 0, 0, TimeSpan.Zero));

    private static readonly FirebaseBindingProposal Proposal =
        new("firebase-uid-1", "google.com", "google-sub-1", 3001, "car***@gmail.com", "Carol");

    private SocialBindingTokenService Sut => new(
        Options.Create(new SocialIdentityOptions
        {
            SigningKey = new string('c', 64),
            BindingTokenLifetime = TimeSpan.FromMinutes(5),
        }),
        _clock);

    [Fact]
    public void AProposalSurvivesTheRoundTripIntact()
    {
        var sut = Sut;

        var opened = sut.Open(sut.Issue(Proposal));

        opened.FirebaseUid.ShouldBe("firebase-uid-1");
        opened.Provider.ShouldBe("google.com");
        opened.ProviderUid.ShouldBe("google-sub-1");
        opened.TargetUserId.ShouldBe(3001);
        opened.EmailMasked.ShouldBe("car***@gmail.com");
        opened.Name.ShouldBe("Carol");
    }

    /// <summary>
    /// The expiry is the service's to set. A caller that could choose it could mint a proposal that
    /// never dies, which is the difference between a five-minute consent window and a permanent
    /// account-linking credential.
    /// </summary>
    [Fact]
    public void AnExpiryChosenByTheCallerIsOverwritten()
    {
        var sut = Sut;

        var opened = sut.Open(sut.Issue(Proposal with { ExpiresAt = 99_999_999_999 }));

        opened.ExpiresAt.ShouldBe((_clock.UtcNow + TimeSpan.FromMinutes(5)).ToUnixTimeSeconds());
    }

    [Fact]
    public void AnExpiredProposalIsRefused()
    {
        var sut = Sut;
        var token = sut.Issue(Proposal);

        _clock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));

        Should.Throw<UnauthorizedException>(() => sut.Open(token))
            .ErrorCode.ShouldBe(ErrorCodes.BindingTokenInvalid);
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("a.b")]
    public void AMalformedProposalIsRefused(string token)
    {
        Should.Throw<UnauthorizedException>(() => Sut.Open(token))
            .ErrorCode.ShouldBe(ErrorCodes.BindingTokenInvalid);
    }

    [Fact]
    public void ATamperedProposalIsRefused()
    {
        var sut = Sut;

        Should.Throw<UnauthorizedException>(() => sut.Open(sut.Issue(Proposal) + "x"));
    }

    /// <summary>
    /// A proposal naming no account is not a proposal. Without this the confirm path would look up
    /// user 0 and report a plain 404, which reads like a deleted account rather than a forged token.
    /// </summary>
    [Fact]
    public void AProposalWithNoTargetAccountIsRefused()
    {
        var sut = Sut;

        Should.Throw<UnauthorizedException>(() => sut.Open(sut.Issue(Proposal with { TargetUserId = 0 })));
    }
}
