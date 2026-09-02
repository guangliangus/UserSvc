using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Abstractions;
using UserSvc.Domain.Auth;
using Xunit;

namespace UserSvc.UnitTests.Platform;

/// <summary>
/// The two default members on <see cref="ICurrentUser"/> that pair the caller's id with the plane
/// it came from.
/// <para>
/// They are default implementations rather than members each adapter restates, so the pairing
/// cannot be done differently in two places - and they are tested here rather than through the
/// HTTP adapter because the pairing is the part that carries the rule.
/// </para>
/// </summary>
public sealed class CurrentUserRealmTests
{
    /// <summary>A caller with whatever id and realm the test wants; nothing else is needed.</summary>
    private static ICurrentUser Caller(int? userId, string realm) => new StubCaller(userId, realm);

    private sealed class StubCaller(int? userId, string realm) : ICurrentUser
    {
        public int? UserId => userId;

        public string? SessionId => "sid";

        public string Realm => realm;

        public int RequireUserId() =>
            UserId ?? throw new UnauthorizedException(ErrorCodes.Unauthorized, "Authentication is required.");
    }

    [Fact]
    public void AConsumerCallerBecomesAConsumerSubject() =>
        Caller(7, SessionRealms.Consumer).RequireSubject()
            .ShouldBe(SessionSubject.Consumer(7));

    [Fact]
    public void ABackOfficeCallerBecomesABackOfficeSubject() =>
        Caller(7, SessionRealms.BackOffice).RequireSubject()
            .ShouldBe(SessionSubject.BackOffice(7));

    /// <summary>
    /// The two subjects for one integer are different values, which is the whole reason the pairing
    /// exists: a device list, an eviction and a sign-out sweep all key on this.
    /// </summary>
    [Fact]
    public void TheSameIdInTheTwoPlanesIsTwoDifferentSubjects() =>
        Caller(7, SessionRealms.Consumer).RequireSubject()
            .ShouldNotBe(Caller(7, SessionRealms.BackOffice).RequireSubject());

    /// <summary>An adapter that reports a realm this service does not know is refused rather than
    /// defaulted: a fallback would point a revocation sweep at the wrong plane, silently.</summary>
    [Fact]
    public void AnUnknownRealmIsRefusedRatherThanDefaulted() =>
        Should.Throw<DomainRuleException>(() => Caller(7, "SUPPLIER").RequireSubject())
            .ErrorCode.ShouldBe("SESSION_REALM_REQUIRED");

    [Fact]
    public void AConsumerMayActOnAConsumerEndpoint() =>
        Caller(7, SessionRealms.Consumer).RequireConsumerId().ShouldBe(7);

    /// <summary>
    /// The measured hole this closes: a back-office access token satisfies a bare
    /// <c>[Authorize]</c> because both planes are served by one OpenIddict instance, and its
    /// <c>sub</c> is an <c>iam.backend_users</c> id that a consumer endpoint would look up in
    /// <c>identity.users</c>. Against a running host, operator 1 read consumer 1's profile at 200.
    /// </summary>
    [Fact]
    public void ABackOfficeCallerMayNotActOnAConsumerEndpoint()
    {
        var error = Should.Throw<ForbiddenException>(
            () => Caller(1, SessionRealms.BackOffice).RequireConsumerId());

        error.ErrorCode.ShouldBe(ErrorCodes.Forbidden);
        error.StatusCode.ShouldBe(403);
    }

    /// <summary>The refusal must not double as an existence oracle: it is decided by the presented
    /// token's own plane, never by whether the id names anybody.</summary>
    [Fact]
    public void TheConsumerGuardIsCheckedBeforeAnythingIsLookedUp() =>
        Should.Throw<ForbiddenException>(
            () => Caller(999_999, SessionRealms.BackOffice).RequireConsumerId());

    [Fact]
    public void AnUnauthenticatedCallerIsStill401NotForbidden() =>
        Should.Throw<UnauthorizedException>(() => Caller(null, SessionRealms.Consumer).RequireConsumerId())
            .ErrorCode.ShouldBe(ErrorCodes.Unauthorized);
}
