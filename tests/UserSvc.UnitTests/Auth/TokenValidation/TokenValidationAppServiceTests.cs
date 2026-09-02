using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Auth.TokenValidation;
using UserSvc.Application.Ports.Auth;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Iam;
using Xunit;

namespace UserSvc.UnitTests.Auth.TokenValidation;

/// <summary>
/// What the introspection endpoint answers is a contract two other services branch on, so the
/// three-state authority shape and the liveness rules are pinned here rather than left to the
/// controller.
/// </summary>
public sealed class TokenValidationAppServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 2, 12, 0, 0, TimeSpan.Zero);

    private readonly IBackOfficeCaller _caller = Substitute.For<IBackOfficeCaller>();
    private readonly IUserSessionRepository _sessions = Substitute.For<IUserSessionRepository>();

    public TokenValidationAppServiceTests()
    {
        _caller.UserId.Returns(42);
        _caller.ActType.Returns(string.Empty);
        _caller.ActCode.Returns(string.Empty);
        _caller.ActDim.Returns(string.Empty);
        _caller.Authz.Returns(EffectiveAuthz.Empty);
    }

    /// <summary>
    /// A consumer token leaves all four authority fields null, and that is not the same as empty.
    /// A relying service reads null as "the question does not apply" and empty as "this person was
    /// granted nothing" - swap them and every consumer is locked out of the relying service.
    /// </summary>
    [Fact]
    public async Task AConsumerTokenReportsNoAuthorityFieldsAtAll()
    {
        var response = await Describe(Facts());

        response.IsValid.ShouldBeTrue();
        response.UserId.ShouldBe(42);
        response.IsInternal.ShouldBeFalse();
        response.Roles.ShouldBeNull();
        response.Permissions.ShouldBeNull();
        response.Menus.ShouldBeNull();
        response.Scopes.ShouldBeNull();
        response.ActiveTenant.ShouldBeNull();
        response.IsTenantAdmin.ShouldBeFalse();
    }

    /// <summary>
    /// The fail-closed direction for the test-user flag: false hides the test company's products.
    /// The whitelist store itself belongs to a slice that has not landed, and reporting true
    /// without one would expose test inventory to every consumer.
    /// </summary>
    [Fact]
    public async Task TheTestUserFlagIsFalseUntilTheWhitelistStoreExists() =>
        (await Describe(Facts())).IsTest.ShouldBeFalse();

    /// <summary>
    /// A back-office caller who holds nothing gets empty lists and a fully declared scope envelope.
    /// The envelope matters most: an absent dimension is read downstream as "unrestricted", so
    /// shipping <see cref="EffectiveAuthz.Empty"/>'s empty dictionary as-is would turn a caller who
    /// holds nothing into one who may read everything.
    /// </summary>
    [Fact]
    public async Task ABackOfficeTokenWithNoAuthoritySaysSoExplicitly()
    {
        var response = await Describe(Facts() with { IsInternal = true });

        response.Roles.ShouldBeEmpty();
        response.Permissions.ShouldBeEmpty();
        response.Menus.ShouldBeEmpty();

        response.Scopes.ShouldNotBeNull();
        response.Scopes!.Keys.ShouldBe(["supplier", "company"], ignoreOrder: true);
        response.Scopes["company"].Values.ShouldBeEmpty();
        response.Scopes["company"].IsGlobal.ShouldBeFalse();
        response.Scopes["supplier"].IsGlobal.ShouldBeFalse();
    }

    /// <summary>
    /// The authority comes from the same face the permission gates read. Two code paths computing
    /// it would drift, and with a five-minute snapshot cache behind them the drift would be
    /// intermittent - the worst kind.
    /// </summary>
    [Fact]
    public async Task TheAuthorityIsWhateverThePipelineAlreadyResolved()
    {
        _caller.ActType.Returns("COMPANY");
        _caller.ActCode.Returns("C001");
        _caller.Authz.Returns(new EffectiveAuthz(
            ["tenant-admin"],
            ["uam.member.read"],
            ["members"],
            new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
            {
                ["company"] = new(["C001"], false),
            }));

        var response = await Describe(Facts() with { IsInternal = true, IsTenantAdmin = true });

        response.Roles.ShouldBe(["tenant-admin"]);
        response.Permissions.ShouldBe(["uam.member.read"]);
        response.Menus.ShouldBe(["members"]);
        response.IsTenantAdmin.ShouldBeTrue();
        response.ActiveTenant.ShouldNotBeNull();
        response.ActiveTenant!.Type.ShouldBe("company");
        response.ActiveTenant.CompanyCode.ShouldBe("C001");
        response.ActiveTenant.SupplierCode.ShouldBeEmpty();
    }

    /// <summary>
    /// A supplier context reports the company its supplier is mounted on, and that is only knowable
    /// from the data-scope envelope: the act claim carries the supplier code and nothing else.
    /// </summary>
    [Fact]
    public async Task ASupplierContextAlsoReportsTheCompanyItIsMountedOn()
    {
        _caller.ActType.Returns("SUPPLIER");
        _caller.ActCode.Returns("S900");
        _caller.Authz.Returns(new EffectiveAuthz(
            [], [], [],
            new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
            {
                ["company"] = new(["C001"], false),
                ["supplier"] = new(["S900"], false),
            }));

        var response = await Describe(Facts() with { IsInternal = true });

        response.ActiveTenant.ShouldNotBeNull();
        response.ActiveTenant!.Type.ShouldBe("supplier");
        response.ActiveTenant.SupplierCode.ShouldBe("S900");
        response.ActiveTenant.CompanyCode.ShouldBe("C001");
    }

    /// <summary>
    /// The token proves authentication and carries no authorization context. Answering an empty
    /// authority instead would read as "this person holds nothing", when in fact nobody has asked
    /// them yet which company they are acting for.
    /// </summary>
    [Fact]
    public async Task APreTenantTokenIsRefusedRatherThanDescribed()
    {
        var error = await Should.ThrowAsync<UnauthorizedException>(
            () => Describe(Facts() with { IsInternal = true, AwaitingTenantContext = true }));

        error.ErrorCode.ShouldBe(ErrorCodes.TenantContextRequired);
    }

    /// <summary>
    /// The one question local JWKS validation cannot answer, and the reason the endpoint survived
    /// the port at all: the token is still cryptographically perfect and the session behind it is
    /// gone.
    /// </summary>
    [Fact]
    public async Task ASignedOutSessionIsRefusedEvenThoughItsTokenIsStillValid()
    {
        var session = StartSession();
        session.Revoke("user-signed-out", Now);
        _sessions.FindBySessionIdAsync("sid-1", Arg.Any<CancellationToken>()).Returns(session);

        var error = await Should.ThrowAsync<UnauthorizedException>(
            () => Describe(Facts() with { SessionId = "sid-1" }));

        error.ErrorCode.ShouldBe(ErrorCodes.SessionRevoked);
    }

    /// <summary>
    /// Only consumer device logins write a session row, so a back-office credential has a sid with
    /// nothing behind it. Refusing on absence would take the whole back office down over a table it
    /// does not populate.
    /// </summary>
    [Fact]
    public async Task AMissingSessionRowIsNotARefusal()
    {
        _sessions.FindBySessionIdAsync("sid-unknown", Arg.Any<CancellationToken>())
            .Returns((UserSession?)null);

        var response = await Describe(Facts() with { SessionId = "sid-unknown", IsInternal = true });

        response.IsValid.ShouldBeTrue();
        response.Platform.ShouldBeEmpty();
        response.DeviceId.ShouldBeEmpty();
    }

    /// <summary>The session row is the only place the device is recorded - the access token carries
    /// two claims and neither of them is a device.</summary>
    [Fact]
    public async Task TheDeviceIsReportedFromTheSessionRow()
    {
        _sessions.FindBySessionIdAsync("sid-1", Arg.Any<CancellationToken>()).Returns(StartSession());

        var response = await Describe(Facts() with { SessionId = "sid-1" });

        response.Platform.ShouldBe("ios");
        response.DeviceId.ShouldBe("device-7");
        response.SessionId.ShouldBe("sid-1");
    }

    /// <summary>A token with no session claim never touches the repository: there is nothing to
    /// look up, and a lookup for the empty string would be a table scan waiting to happen.</summary>
    [Fact]
    public async Task ATokenWithNoSessionClaimIsNotLookedUp()
    {
        await Describe(Facts());

        await _sessions.DidNotReceiveWithAnyArgs()
            .FindBySessionIdAsync(default!, default);
    }

    [Fact]
    public async Task TheRemainingLifetimeIsCountedFromTheClock() =>
        (await Describe(Facts() with { ExpiresAt = Now.AddMinutes(10) })).ExpiresIn.ShouldBe(600);

    /// <summary>
    /// An already-expired token floors at zero rather than reporting a negative lifetime. It can
    /// happen: the authentication stack's clock skew allowance is wider than none.
    /// </summary>
    [Fact]
    public async Task AnExpiryInThePastFloorsAtZero() =>
        (await Describe(Facts() with { ExpiresAt = Now.AddMinutes(-1) })).ExpiresIn.ShouldBe(0);

    /// <summary>
    /// A principal with no lifetime - what the development authentication handler fabricates -
    /// reports zero rather than refusing. Whether a session is alive is a different question from
    /// how long its token has left.
    /// </summary>
    [Fact]
    public async Task APrincipalWithNoLifetimeReportsZeroRatherThanFailing()
    {
        var response = await Describe(Facts() with { ExpiresAt = null, IssuedAt = null });

        response.ExpiresIn.ShouldBe(0);
        response.ExpiresAt.ShouldBeNull();
        response.IssuedAt.ShouldBeNull();
    }

    /// <summary>
    /// A session row that belongs to a different account answers nothing. Reporting from it would
    /// hand this caller another account's device and platform, and would take the liveness verdict
    /// - the one thing this endpoint exists to answer - from that account's session rather than
    /// this one's.
    /// </summary>
    [Fact]
    public async Task ASessionRowBelongingToAnotherAccountIsRefusedRatherThanReportedFrom()
    {
        _sessions.FindBySessionIdAsync("sid-1", Arg.Any<CancellationToken>()).Returns(
            UserSession.Start(
                "sid-1",
                99,
                new DeviceDescriptor("device-9", "someone else", "android", "1.0.0", "198.51.100.4", "agent"),
                "auth-9",
                Now));

        var error = await Should.ThrowAsync<UnauthorizedException>(
            () => Describe(Facts() with { SessionId = "sid-1" }));

        error.ErrorCode.ShouldBe(ErrorCodes.InvalidToken);
    }

    /// <summary>Zero is "no caller" everywhere in this codebase; reporting an authority face for it
    /// would be reporting somebody else's.</summary>
    [Fact]
    public async Task AnUnidentifiedCallerIsRefused()
    {
        _caller.UserId.Returns(0);

        var error = await Should.ThrowAsync<UnauthorizedException>(() => Describe(Facts()));

        error.ErrorCode.ShouldBe(ErrorCodes.Unauthorized);
    }

    private static ValidatedTokenFacts Facts() => new()
    {
        IssuedAt = Now.AddMinutes(-1),
        ExpiresAt = Now.AddMinutes(9),
    };

    private static UserSession StartSession() => UserSession.Start(
        "sid-1",
        42,
        new DeviceDescriptor("device-7", "Alan's phone", "ios", "3.1.0", "203.0.113.7", "agent"),
        "auth-1",
        Now);

    private Task<TokenValidationResponse> Describe(ValidatedTokenFacts facts)
    {
        var clock = Substitute.For<IClock>();
        clock.UtcNow.Returns(Now);

        var service = new TokenValidationAppService(
            _caller, _sessions, clock, NullLogger<TokenValidationAppService>.Instance);

        return service.DescribeAsync(facts, CancellationToken.None);
    }
}
