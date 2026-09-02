using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
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

    /// <summary>
    /// A no-authority sign-in and a pre-tenant sign-in both carry no act, and they must still be
    /// told apart: the first one is <b>finished</b> and gets a real credential with an empty
    /// authority surface, the second is half a sign-in and gets a pre-tenant one. When
    /// <c>ContextRequired</c> was <c>ActType.Length == 0</c> it answered true for both, so the
    /// REST response said <c>contextRequired: false, grantedScope: backoffice</c> while the token
    /// endpoint minted <c>backoffice_pre_tenant</c> - and a freshly created operator could sign in
    /// and never get a usable credential.
    /// </summary>
    [Fact]
    public void ASignInWithNoAuthorityIsFinishedRatherThanPreTenant()
    {
        var settled = BackOfficeSignInTicket.ForContext(57, "operator", 3, act: null);
        var preTenant = BackOfficeSignInTicket.PreTenant(57, "operator", 3);

        settled.ToActClaim().ShouldBeNull();
        preTenant.ToActClaim().ShouldBeNull("both outcomes carry no act - that is the point");

        settled.ContextRequired.ShouldBeFalse();
        preTenant.ContextRequired.ShouldBeTrue();
    }

    /// <summary>The distinction is only worth anything if it survives being signed and reopened by
    /// the pod that redeems the ticket, which is a different process from the one that minted
    /// it.</summary>
    [Fact]
    public void TheFinishedSignInFlagSurvivesTheRoundTrip()
    {
        var opened = Sut().Open(Sut().Issue(
            BackOfficeSignInTicket.ForContext(57, "operator", 3, act: null)));

        opened.ContextSettled.ShouldBeTrue();
        opened.ContextRequired.ShouldBeFalse();
        opened.ToActClaim().ShouldBeNull();
    }

    /// <summary>
    /// A ticket minted by a build that did not write the flag has no <c>cs</c> member, so it
    /// deserializes to false and is read as a sign-in still owing a context: a five-minute
    /// credential reaching two endpoints. That is the direction the default has to fall. The
    /// opposite phrasing would have upgraded every in-flight pre-tenant ticket to a full
    /// back-office token with a refresh chain for the two minutes after a deployment.
    /// </summary>
    [Fact]
    public void ATicketFromABuildThatWroteNoFlagIsReadAsStillOwingAContext()
    {
        // A finished no-authority sign-in, then the flag deleted and the payload re-signed with the
        // real key - so the absent member is the only thing that can change the reading.
        var issued = Sut().Issue(BackOfficeSignInTicket.ForContext(57, "operator", 3, act: null));
        var json = Encoding.UTF8.GetString(
            Base64Url.DecodeFromChars(issued.AsSpan(0, issued.IndexOf('.', StringComparison.Ordinal))));

        json.ShouldContain("\"cs\":true");

        var opened = Sut().Open(ReSign(Regex.Replace(json, ",?\"cs\":true", string.Empty)));

        opened.ContextSettled.ShouldBeFalse();
        opened.ContextRequired.ShouldBeTrue();
    }

    /// <summary>Re-signs a hand-edited payload with the real key, so that what the test changed is
    /// the only thing the reader can object to.</summary>
    private static string ReSign(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        byte[] signed = [.. Encoding.ASCII.GetBytes("usersvc/back-office-sign-in/v1"), .. bytes];

        return Base64Url.EncodeToString(bytes) + "." + Base64Url.EncodeToString(
            HMACSHA256.HashData(Convert.FromHexString(Key), signed));
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
    /// Every ticket carries an id, and no two carry the same one - which is what the consume-once
    /// marker is keyed on. Two tickets sharing an id would mean redeeming either spent both.
    /// </summary>
    [Fact]
    public void EveryTicketCarriesADistinctId()
    {
        var ids = Enumerable
            .Range(0, 32)
            .Select(_ => Sut().Open(Sut().Issue(BackOfficeSignInTicket.PreTenant(57, "operator", 3))).TicketId)
            .ToList();

        ids.ShouldAllBe(id => id.Length >= 22);
        ids.Distinct(StringComparer.Ordinal).Count().ShouldBe(ids.Count);
    }

    /// <summary>
    /// The id is written by the issuer, exactly like the expiry. A caller that chose its own could
    /// reuse one - deliberately, to make a second ticket the first redemption had already spent,
    /// or to burn an id somebody else was about to be issued.
    /// </summary>
    [Fact]
    public void TheIssuerDecidesTheIdAndTheCallerCannotChooseIt()
    {
        var chosen = BackOfficeSignInTicket.PreTenant(57, "operator", 3) with
        {
            TicketId = "an-id-the-caller-picked",
        };

        Sut().Open(Sut().Issue(chosen)).TicketId.ShouldNotBe("an-id-the-caller-picked");
    }

    /// <summary>
    /// A ticket with no id cannot be claimed in the marker store, so it cannot be shown to be
    /// unredeemed - and the fail-closed answer to that is to refuse it. The only ticket that can be
    /// in this state is one an older build minted, so the blast radius is a two-minute window after
    /// a deployment in which a sign-in that straddled the upgrade is answered "sign in again". That
    /// beats accepting unlimited replays of every ticket minted before the marker existed.
    /// </summary>
    [Fact]
    public void ATicketFromABuildThatWroteNoIdDoesNotOpen()
    {
        // Re-signed with the real key, so the missing id is the only thing that can refuse it.
        var issued = Sut().Issue(BackOfficeSignInTicket.PreTenant(57, "operator", 3));
        var payload = issued[..issued.IndexOf('.', StringComparison.Ordinal)];
        var json = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(payload));

        json.ShouldContain("\"jti\"");

        var bytes = Encoding.UTF8.GetBytes(
            Regex.Replace(json, "\"jti\":\"[^\"]*\"", "\"jti\":\"\""));

        byte[] signed = [.. Encoding.ASCII.GetBytes("usersvc/back-office-sign-in/v1"), .. bytes];
        var resigned = Base64Url.EncodeToString(bytes) + "." + Base64Url.EncodeToString(
            HMACSHA256.HashData(Convert.FromHexString(Key), signed));

        Should.Throw<UnauthorizedException>(() => Sut().Open(resigned))
            .ErrorCode.ShouldBe(ErrorCodes.InvalidToken);
    }

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
