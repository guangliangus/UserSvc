using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.SignIn;
using UserSvc.Domain.Tenancy;
using Xunit;

namespace UserSvc.UnitTests.BackOffice.SignIn;

/// <summary>
/// The sign-in ticket. It is a bearer credential for the account it names, so the cases that matter
/// are the ones where it must <i>not</i> open: a tampered payload, a foreign signature, an expired
/// window, and an unconfigured key.
/// </summary>
public sealed class BackOfficeSignInTicketServiceTests
{
    private const string Key =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    private const string OtherKey =
        "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 9, 0, 0, TimeSpan.Zero));

    private BackOfficeSignInTicketService Sut(string key = Key, TimeSpan? lifetime = null) =>
        new(
            Options.Create(new BackOfficeSignInOptions
            {
                SignInTicketKey = key,
                SignInTicketLifetime = lifetime ?? TimeSpan.FromMinutes(2),
            }),
            _clock);

    [Fact]
    public void ATicketOpensBackIntoWhatWasPutIntoIt()
    {
        var issued = Sut().Issue(BackOfficeSignInTicket.ForContext(
            57, "Wang Xiaoming", 11, new ActClaim(ActTypes.Company, "C1", string.Empty, IsAdmin: true)));

        var opened = Sut().Open(issued);

        opened.UserId.ShouldBe(57);
        opened.ActorName.ShouldBe("Wang Xiaoming");
        opened.TokenVersion.ShouldBe(11);
        opened.ContextRequired.ShouldBeFalse();

        var act = opened.ToActClaim().ShouldNotBeNull();
        act.Type.ShouldBe(ActTypes.Company);
        act.Code.ShouldBe("C1");
        act.IsAdmin.ShouldBeTrue();
    }

    /// <summary>
    /// A pre-tenant ticket carries no act, and that absence is a positive statement by the issuer -
    /// it is what makes the redeemed token a pre-tenant one.
    /// </summary>
    [Fact]
    public void APreTenantTicketCarriesNoContext()
    {
        var opened = Sut().Open(Sut().Issue(BackOfficeSignInTicket.PreTenant(57, "operator", 3)));

        opened.ContextRequired.ShouldBeTrue();
        opened.ToActClaim().ShouldBeNull();
    }

    /// <summary>A no-authority sign-in and a pre-tenant sign-in both carry no act. What separates
    /// them is the scope the redeemer grants, which is not this record's decision.</summary>
    [Fact]
    public void ASignInWithNoAuthorityAlsoCarriesNoContext()
    {
        var ticket = BackOfficeSignInTicket.ForContext(57, "operator", 3, act: null);

        ticket.ContextRequired.ShouldBeTrue();
        ticket.ToActClaim().ShouldBeNull();
    }

    [Fact]
    public void ATamperedPayloadDoesNotOpen()
    {
        var issued = Sut().Issue(BackOfficeSignInTicket.PreTenant(57, "operator", 3));
        var separator = issued.IndexOf('.', StringComparison.Ordinal);

        // One character of the payload, with the signature left as it was.
        var tampered = issued[..(separator - 1)] + (issued[separator - 1] == 'A' ? 'B' : 'A')
                       + issued[separator..];

        Should.Throw<UnauthorizedException>(() => Sut().Open(tampered))
            .ErrorCode.ShouldBe(ErrorCodes.InvalidToken);
    }

    /// <summary>A ticket signed with another key does not open. Without this, a leaked key from any
    /// other environment would mint tickets for this one.</summary>
    [Fact]
    public void ATicketSignedWithAnotherKeyDoesNotOpen()
    {
        var foreign = Sut(OtherKey).Issue(BackOfficeSignInTicket.PreTenant(57, "operator", 3));

        Should.Throw<UnauthorizedException>(() => Sut().Open(foreign));
    }

    /// <summary>
    /// The expiry is written by the issuer, so a caller cannot ask for a long-lived ticket by
    /// putting a distant one in the record it hands over.
    /// </summary>
    [Fact]
    public void TheIssuerDecidesTheExpiryAndTheCallerCannotExtendIt()
    {
        var greedy = BackOfficeSignInTicket.PreTenant(57, "operator", 3) with
        {
            ExpiresAt = _clock.UtcNow.AddYears(1).ToUnixTimeSeconds(),
        };

        var issued = Sut(lifetime: TimeSpan.FromMinutes(2)).Issue(greedy);

        _clock.Advance(TimeSpan.FromMinutes(3));

        Should.Throw<UnauthorizedException>(() => Sut().Open(issued));
    }

    [Fact]
    public void ATicketOpensInsideItsWindowAndNotAfterIt()
    {
        var issued = Sut(lifetime: TimeSpan.FromMinutes(2))
            .Issue(BackOfficeSignInTicket.PreTenant(57, "operator", 3));

        _clock.Advance(TimeSpan.FromSeconds(119));
        Sut().Open(issued).UserId.ShouldBe(57);

        _clock.Advance(TimeSpan.FromSeconds(2));
        Should.Throw<UnauthorizedException>(() => Sut().Open(issued));
    }

    [Theory]
    [InlineData("")]
    [InlineData("no-separator")]
    [InlineData("payload.")]
    [InlineData(".signature")]
    [InlineData("not!base64url.not!base64url")]
    public void AMalformedTicketDoesNotOpen(string ticket) =>
        Should.Throw<UnauthorizedException>(() => Sut().Open(ticket));

    /// <summary>
    /// An act type this build does not recognise is read as "no context" rather than passed on. The
    /// context funnel answers an unknown type with a 500, and a value that arrived through a
    /// signature an older build produced is data, not a server fault.
    /// </summary>
    [Fact]
    public void AnUnknownContextTypeIsReadAsNoContext()
    {
        var issued = Sut().Issue(new BackOfficeSignInTicket(
            57, "operator", 3, "MARS", "C1", string.Empty, ActIsAdmin: true));

        var opened = Sut().Open(issued);

        opened.ToActClaim().ShouldBeNull();
        opened.ContextRequired.ShouldBeTrue();
        opened.ActIsAdmin.ShouldBeFalse();
    }

    /// <summary>
    /// A deployment with no key configured refuses with the section named and a 500
    /// <c>NOT_CONFIGURED</c> - not <c>INTERNAL_ERROR</c> - so an operator goes and looks at the
    /// secrets rather than at the code.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("not-hex-at-all")]
    [InlineData("00112233")]
    public void AnUnusableKeyRefusesWithTheSectionNamed(string key)
    {
        var failure = Should.Throw<AppException>(() =>
            Sut(key).Issue(BackOfficeSignInTicket.PreTenant(57, "operator", 3)));

        failure.ErrorCode.ShouldBe(ErrorCodes.NotConfigured);
        failure.StatusCode.ShouldBe(500);
        failure.Message.ShouldContain("BackOfficeSignIn:SignInTicketKey");
    }

    /// <summary>
    /// Constructing the service must not throw on an unconfigured deployment: it is built on the
    /// token endpoint's own graph, and a constructor that read the key would take consumer sign-in
    /// down with it.
    /// </summary>
    [Fact]
    public void ConstructingTheServiceWithNoKeyDoesNotThrow() =>
        Should.NotThrow(() => Sut(string.Empty));

    /// <summary>
    /// The two scope names the sign-in response advertises are the same two the API layer's
    /// policies are built on. They are duplicated across a project boundary the application layer
    /// may not cross, so the literals are pinned here: if they drift, a sign-in advertises a scope
    /// the token endpoint refuses.
    /// </summary>
    [Fact]
    public void TheAdvertisedScopeNamesMatchThePolicies()
    {
        BackOfficeSignInScopes.BackOffice.ShouldBe("backoffice");
        BackOfficeSignInScopes.PreTenant.ShouldBe("backoffice_pre_tenant");
    }
}
