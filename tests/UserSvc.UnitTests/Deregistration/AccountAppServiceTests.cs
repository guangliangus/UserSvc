using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Account;
using UserSvc.Application.Features.Sessions;
using UserSvc.Application.Ports.Auth;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Users;
using UserSvc.Domain.Users.Events;
using Xunit;

namespace UserSvc.UnitTests.Deregistration;

/// <summary>
/// Deregistration, which is the one thing here a consumer cannot undo.
/// <para>
/// <see cref="SessionAppService"/> is constructed for real rather than substituted - it is sealed,
/// and more to the point the thing worth testing is precisely the interaction between the two: that
/// every session really is dead before the account is closed, and that failing to kill them stops
/// the whole thing.
/// </para>
/// </summary>
public sealed class AccountAppServiceTests
{
    private const int UserId = 7;

    private readonly IUserRepository _users = Substitute.For<IUserRepository>();
    private readonly IUserIdentityRepository _identities = Substitute.For<IUserIdentityRepository>();
    private readonly IUserSessionRepository _sessions = Substitute.For<IUserSessionRepository>();
    private readonly ISessionRevocationStore _revocations = Substitute.For<ISessionRevocationStore>();
    private readonly ITokenChainRevoker _chains = Substitute.For<ITokenChainRevoker>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 8, 0, 0, TimeSpan.Zero));

    private readonly User _user = new() { Id = UserId, Status = UserStatuses.Active };

    public AccountAppServiceTests()
    {
        _users.FindByIdAsync(UserId, Arg.Any<CancellationToken>()).Returns(_user);
        _identities.ListActiveByUserAsync(UserId, Arg.Any<CancellationToken>()).Returns([]);
        _sessions.ListActiveByUserAsync(UserId, Arg.Any<CancellationToken>()).Returns([]);

        // The substitute has to run the body, or every assertion here would pass against a
        // transaction that never opened.
        _unitOfWork.ExecuteInTransactionAsync(
                Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns(call => call.Arg<Func<CancellationToken, Task>>().Invoke(CancellationToken.None));
    }

    private AccountAppService Sut => new(
        _users,
        _identities,
        new SessionAppService(
            _sessions,
            _users,
            _revocations,
            _chains,
            _unitOfWork,
            _clock,
            Options.Create(new AuthSessionOptions()),
            NullLogger<SessionAppService>.Instance),
        _unitOfWork,
        _clock,
        NullLogger<AccountAppService>.Instance);

    private static UserIdentity Identity(int id, string type, string hash) => new()
    {
        Id = id,
        UserId = UserId,
        IdentityType = type,
        IdentifierHash = hash,
        Status = UserStatuses.Active,
    };

    /// <summary>
    /// Models the real repository, which only ever returns rows still marked ACTIVE - so a session
    /// revoked by the first sweep is gone by the second. A substitute that kept handing the same
    /// list back would quietly make both sweeps look identical.
    /// </summary>
    private void ActiveSessionsPerCall(params IReadOnlyList<UserSession>[] perCall)
    {
        var call = 0;
        _sessions.ListActiveByUserAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(_ => call < perCall.Length ? perCall[call++] : []);
    }

    private UserSession Session(string sessionId, string authorizationId) => UserSession.Start(
        sessionId,
        UserId,
        new DeviceDescriptor("dev-" + sessionId, "iPhone", "IOS", "3.2.0", "203.0.113.7", "ua"),
        authorizationId,
        _clock.UtcNow);

    [Fact]
    public async Task AnUnknownAccountIs404AndNothingIsRevoked()
    {
        _users.FindByIdAsync(UserId, Arg.Any<CancellationToken>()).Returns((User?)null);

        var ex = await Should.ThrowAsync<NotFoundException>(
            () => Sut.DeregisterAsync(UserId, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.UserNotFound);
        await _revocations.DidNotReceiveWithAnyArgs().RevokeAsync(default!, default, default);
    }

    [Fact]
    public async Task TheAccountAndEveryLoginIdentityGoDisabled()
    {
        var phone = Identity(1, IdentityTypes.Phone, "hash-phone");
        var email = Identity(2, IdentityTypes.Email, "hash-email");
        _identities.ListActiveByUserAsync(UserId, Arg.Any<CancellationToken>()).Returns([phone, email]);

        await Sut.DeregisterAsync(UserId, CancellationToken.None);

        _user.Status.ShouldBe(UserStatuses.Disabled);
        _user.UpdatedAt.ShouldBe(_clock.UtcNow);
        phone.Status.ShouldBe(UserStatuses.Disabled);
        email.Status.ShouldBe(UserStatuses.Disabled);
    }

    [Fact]
    public async Task NothingIsPhysicallyDeleted()
    {
        // There is no delete on any port this service holds, so the only way a row could vanish is
        // through raw SQL. This test is the tripwire for someone adding one.
        await Sut.DeregisterAsync(UserId, CancellationToken.None);

        _user.Status.ShouldBe(UserStatuses.Disabled,
            "deregistration is a soft close: the profile, the feedback and the audit trail all stay");
    }

    [Fact]
    public async Task DisablingTheIdentitiesIsWhatReleasesThePhoneNumberForReuse()
    {
        var phone = Identity(1, IdentityTypes.Phone, "hash-phone");
        _identities.ListActiveByUserAsync(UserId, Arg.Any<CancellationToken>()).Returns([phone]);

        await Sut.DeregisterAsync(UserId, CancellationToken.None);

        // The unique index covers ACTIVE rows only, so this single assignment is the whole
        // mechanism by which the number becomes registerable again. It is intended: the
        // alternative locks a returning customer, or whoever inherits a recycled number, out
        // permanently.
        phone.Status.ShouldNotBe(UserStatuses.Active);
    }

    [Fact]
    public async Task EverySessionIsRevokedInAllThreePlaces()
    {
        var session = Session("sid-1", "auth-1");
        ActiveSessionsPerCall([session]);

        await Sut.DeregisterAsync(UserId, CancellationToken.None);

        session.IsActive.ShouldBeFalse("the row is the authority the refresh path reads");
        session.RevokedBy.ShouldBe(RevocationReasons.Deregistered);
        await _chains.Received(1).RevokeChainAsync("auth-1", Arg.Any<CancellationToken>());
        await _revocations.Received(1).RevokeAsync(
            "sid-1", Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SessionsDieBeforeTheAccountIsClosed()
    {
        var session = Session("sid-1", "auth-1");
        ActiveSessionsPerCall([session]);

        string? statusWhenRevoked = null;
        _revocations.RevokeAsync(Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(_ =>
            {
                statusWhenRevoked = _user.Status;
                return Task.CompletedTask;
            });

        await Sut.DeregisterAsync(UserId, CancellationToken.None);

        // The order is the safe direction of an unavoidable non-atomicity. Reversed, an interrupted
        // deregistration leaves a closed account holding a live refresh chain - and nothing on the
        // refresh path looks at account status, so it would stay live indefinitely.
        statusWhenRevoked.ShouldBe(UserStatuses.Active);
        _user.Status.ShouldBe(UserStatuses.Disabled);
    }

    [Fact]
    public async Task AnAccountWhoseTokensCouldNotBeKilledIsLeftOpen()
    {
        ActiveSessionsPerCall([Session("sid-1", "auth-1")]);
        _revocations.RevokeAsync(Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new UpstreamException(ErrorCodes.UpstreamUnavailable, "redis is down"));

        await Should.ThrowAsync<UpstreamException>(() => Sut.DeregisterAsync(UserId, CancellationToken.None));

        _user.Status.ShouldBe(UserStatuses.Active,
            "closing an account whose holder keeps a working token is the worst of both outcomes");
    }

    [Fact]
    public async Task TheSessionsAreSweptASecondTimeAfterTheAccountCloses()
    {
        // A sign-in racing the first sweep is allowed - the account is still ACTIVE at that moment -
        // and its session would otherwise outlive the account it belongs to.
        var raced = Session("sid-raced", "auth-raced");
        ActiveSessionsPerCall([], [raced]);

        await Sut.DeregisterAsync(UserId, CancellationToken.None);

        raced.IsActive.ShouldBeFalse();
        await _chains.Received(1).RevokeChainAsync("auth-raced", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ADeregistrationEventCarriesTheReleasedIdentifiersAsHashes()
    {
        _identities.ListActiveByUserAsync(UserId, Arg.Any<CancellationToken>())
            .Returns([Identity(1, IdentityTypes.Phone, "hash-phone")]);

        await Sut.DeregisterAsync(UserId, CancellationToken.None);

        var raised = _user.DomainEvents.OfType<UserDeregistered>().ShouldHaveSingleItem();
        raised.UserId.ShouldBe(UserId);
        raised.OccurredAt.ShouldBe(_clock.UtcNow);

        var unbound = raised.UnboundIdentities.ShouldHaveSingleItem();
        unbound.IdentityType.ShouldBe(IdentityTypes.Phone);
        unbound.IdentifierHash.ShouldBe("hash-phone",
            "the blind index identifies the account precisely and puts no phone number on a bus");
    }

    [Fact]
    public async Task RepeatingItChangesNothingAndPublishesNoSecondEvent()
    {
        _user.Status = UserStatuses.Disabled;

        await Sut.DeregisterAsync(UserId, CancellationToken.None);

        _user.DomainEvents.ShouldBeEmpty();
        await _unitOfWork.DidNotReceive().ExecuteInTransactionAsync(
            Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RepeatingItStillSweepsTheSessions()
    {
        // This is what makes a client retry after a half-completed first attempt worth something.
        _user.Status = UserStatuses.Disabled;
        var leftover = Session("sid-left", "auth-left");
        ActiveSessionsPerCall([leftover]);

        await Sut.DeregisterAsync(UserId, CancellationToken.None);

        leftover.IsActive.ShouldBeFalse();
    }
}
