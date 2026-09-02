using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Consumers;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Features.BackOffice.TestWhitelist;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.TestWhitelist;
using UserSvc.Application.Ports.Users;
using UserSvc.Application.Security;
using UserSvc.Domain.Iam;
using UserSvc.Domain.TestWhitelist;
using UserSvc.Domain.Users;
using Xunit;

namespace UserSvc.UnitTests.TestWhitelist;

/// <summary>
/// The whitelist's administrative half. Three properties dominate: the guard is the account-row
/// super-administrator flag and is read per request, a store failure must never be rendered as "the
/// list is empty", and a write that changed nothing must not leave an audit row claiming it did.
/// </summary>
public sealed class TestWhitelistAppServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 2, 10, 0, 0, TimeSpan.Zero);

    private const int SuperAdminId = 7;

    private readonly IBackOfficeUserDirectory _directory = Substitute.For<IBackOfficeUserDirectory>();
    private readonly ITestWhitelistRepository _whitelist = Substitute.For<ITestWhitelistRepository>();
    private readonly IUserRepository _users = Substitute.For<IUserRepository>();
    private readonly IConsumerAccountDirectory _consumers = Substitute.For<IConsumerAccountDirectory>();
    private readonly IIamAuditLogRepository _auditLog = Substitute.For<IIamAuditLogRepository>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();

    private readonly List<TestWhitelistEntry> _added = [];

    public TestWhitelistAppServiceTests()
    {
        _directory.FindFlagsAsync(SuperAdminId, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(SuperAdminId, BackOfficeUserStatuses.Active, true, 1));

        _whitelist.ListActiveUserIdsAsync(Arg.Any<CancellationToken>()).Returns([]);
        _whitelist.FindAsync(Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns((TestWhitelistEntry?)null);

        _consumers.ListAccountsAsync(Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _consumers.ListActiveContactsAsync(Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);

        _whitelist.When(repository => repository.Add(Arg.Any<TestWhitelistEntry>()))
            .Do(call => _added.Add(call.Arg<TestWhitelistEntry>()));
    }

    private TestWhitelistAppService Sut => new(
        new AdminScopeService(
            _directory,
            Substitute.For<ITenantMemberDirectory>(),
            Substitute.For<IUserTenantRoleRepository>(),
            Substitute.For<IRoleRepository>(),
            Substitute.For<IRoleMenuRepository>(),
            Substitute.For<IMenuRepository>(),
            Substitute.For<IRolePermissionRepository>()),
        _whitelist,
        _users,
        new ConsumerSummaryService(
            _consumers,
            new IdentifierProtector(Options.Create(new IdentifierProtectionOptions
            {
                Pepper = "00112233445566778899aabbccddeeff",
                DataKey = Convert.ToBase64String(new byte[32]),
                KeyVersion = "v3",
            })),
            NullLogger<ConsumerSummaryService>.Instance),
        new IamAuditWriter(_auditLog, new TestClock(Now), NullLogger<IamAuditWriter>.Instance),
        _unitOfWork,
        new TestClock(Now),
        NullLogger<TestWhitelistAppService>.Instance);

    // ---------------------------------------------------------------- the guard

    [Fact]
    public async Task ListRefusesAnAccountThatIsNotThePlatformSuperAdministrator()
    {
        var error = await Should.ThrowAsync<BadRequestException>(() =>
            Sut.ListAsync(OrdinaryCaller(), 1, 20, CancellationToken.None));

        error.ErrorCode.ShouldBe(ErrorCodes.SuperAdminRequired);
        await _whitelist.DidNotReceive().ListActiveUserIdsAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AddRefusesAnAccountThatIsNotThePlatformSuperAdministrator()
    {
        await Should.ThrowAsync<BadRequestException>(() =>
            Sut.AddAsync(OrdinaryCaller(), 4, CancellationToken.None));

        _added.ShouldBeEmpty();
        await _users.DidNotReceive().FindByIdAsync(Arg.Any<int>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RemoveRefusesAnAccountThatIsNotThePlatformSuperAdministrator()
    {
        await Should.ThrowAsync<BadRequestException>(() =>
            Sut.RemoveAsync(OrdinaryCaller(), 4, CancellationToken.None));

        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TheGuardIsReadFromTheAccountRowRatherThanFromTheToken()
    {
        // A caller whose token-resolved face carries every permission there is still gets nothing:
        // the flag lives on the account row, which is what makes a revocation land on the next
        // request instead of at the next sign-in.
        var caller = new WhitelistCaller
        {
            UserId = 99,
            Authz = new EffectiveAuthz(
                [], ["uam.role.manage", "uam.company.manage"], [],
                new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)),
        };
        _directory.FindFlagsAsync(99, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(99, BackOfficeUserStatuses.Active, false, 1));

        await Should.ThrowAsync<BadRequestException>(() =>
            Sut.ListAsync(caller, 1, 20, CancellationToken.None));
    }

    // ---------------------------------------------------------------- the listing

    [Fact]
    public async Task AnUnreachableStoreFailsTheListingRatherThanRenderingItEmpty()
    {
        _whitelist.ListActiveUserIdsAsync(Arg.Any<CancellationToken>())
            .Throws(new InvalidOperationException("the database is down"));

        // An empty list reads as "nobody is whitelisted", which invites an operator to re-add
        // everyone or to believe a removal succeeded.
        await Should.ThrowAsync<InvalidOperationException>(() =>
            Sut.ListAsync(Caller(), 1, 20, CancellationToken.None));
    }

    [Fact]
    public async Task OnlyTheCurrentPageIsHydrated()
    {
        _whitelist.ListActiveUserIdsAsync(Arg.Any<CancellationToken>()).Returns([1, 2, 3, 4, 5]);

        var response = await Sut.ListAsync(Caller(), 2, 2, CancellationToken.None);

        response.Total.ShouldBe(5);
        response.Page.ShouldBe(2);
        response.PageSize.ShouldBe(2);
        response.TotalPages.ShouldBe(3);
        response.Items.Select(item => item.UserId).ShouldBe([3, 4]);

        // Hydrating is what decrypts identifiers, so it must see the page and not the list.
        await _consumers.Received(1).ListAccountsAsync(
            Arg.Is<IReadOnlyList<int>>(ids => ids.SequenceEqual(new[] { 3, 4 })),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TheEchoedPagingIsTheCorrectedPaging()
    {
        _whitelist.ListActiveUserIdsAsync(Arg.Any<CancellationToken>()).Returns([1]);

        var response = await Sut.ListAsync(Caller(), 0, 9999, CancellationToken.None);

        response.Page.ShouldBe(1);
        response.PageSize.ShouldBe(TestWhitelistPaging.MaxPageSize);
    }

    // ---------------------------------------------------------------- adding

    [Fact]
    public async Task AddRefusesAnIdThatIsNotAConsumerAccount()
    {
        _users.FindByIdAsync(4, Arg.Any<CancellationToken>()).Returns((User?)null);

        var error = await Should.ThrowAsync<NotFoundException>(() =>
            Sut.AddAsync(Caller(), 4, CancellationToken.None));

        error.ErrorCode.ShouldBe(ErrorCodes.NotFound);
        _added.ShouldBeEmpty();
    }

    [Theory]
    [InlineData(UserStatuses.Pending)]
    [InlineData(UserStatuses.Disabled)]
    [InlineData(UserStatuses.Deleted)]
    public async Task AddRefusesAnAccountThatCannotSignIn(string status)
    {
        _users.FindByIdAsync(4, Arg.Any<CancellationToken>()).Returns(new User { Id = 4, Status = status });

        // Whitelist membership is inert for an account that cannot obtain a token, and silently
        // accepting one makes the list harder to reason about.
        var error = await Should.ThrowAsync<NotFoundException>(() =>
            Sut.AddAsync(Caller(), 4, CancellationToken.None));

        error.ErrorCode.ShouldBe(ErrorCodes.NotFound);
        _added.ShouldBeEmpty();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task AddRefusesANonPositiveId(int userId)
    {
        var error = await Should.ThrowAsync<BadRequestException>(() =>
            Sut.AddAsync(Caller(), userId, CancellationToken.None));

        error.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
        await _users.DidNotReceive().FindByIdAsync(Arg.Any<int>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AddInsertsTheEntryAndRecordsWhoDidIt()
    {
        ActiveConsumer(4);

        await Sut.AddAsync(Caller(), 4, CancellationToken.None);

        var entry = _added.ShouldHaveSingleItem();
        entry.UserId.ShouldBe(4);
        entry.Status.ShouldBe(TestWhitelistStatuses.Active);
        entry.CreatedBy.ShouldBe("operator");
        entry.CreatedAt.ShouldBe(Now);

        await _unitOfWork.Received(1).SaveChangesAsync(Arg.Any<CancellationToken>());

        var audit = await CapturedAuditAsync();
        audit.Action.ShouldBe(TestWhitelistAuditVocabulary.AddAction);
        audit.TargetType.ShouldBe(TestWhitelistAuditVocabulary.TargetType);
        audit.TargetId.ShouldBe("4");
        audit.ActorUserId.ShouldBe(SuperAdminId);
        audit.TenantType.ShouldBe(IamAuditTenantTypes.Platform);
        audit.BeforeData.ShouldBeNull();
        audit.AfterData.ShouldNotBeNull().ShouldContain("\"status\":\"ACTIVE\"");
    }

    [Fact]
    public async Task AddingAnAccountThatIsAlreadyOnTheListChangesAndRecordsNothing()
    {
        ActiveConsumer(4);
        _whitelist.FindAsync(4, Arg.Any<CancellationToken>()).Returns(Entry(4, TestWhitelistStatuses.Active));

        await Sut.AddAsync(Caller(), 4, CancellationToken.None);

        _added.ShouldBeEmpty();
        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());

        // An idempotent call that wrote an audit row would fill the trail with events that never
        // happened.
        await _auditLog.DidNotReceive().AppendAsync(
            Arg.Any<UserSvc.Domain.Iam.IamAuditLog>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ReAddingARemovedAccountRevivesItsRowRatherThanInsertingASecond()
    {
        ActiveConsumer(4);
        var existing = Entry(4, TestWhitelistStatuses.Removed);
        _whitelist.FindAsync(4, Arg.Any<CancellationToken>()).Returns(existing);

        await Sut.AddAsync(Caller(), 4, CancellationToken.None);

        // A second row would be refused by the partial unique index; reviving also keeps the
        // original CreatedAt, which is the answer to "since when has this account been a tester".
        _added.ShouldBeEmpty();
        existing.Status.ShouldBe(TestWhitelistStatuses.Active);
        existing.UpdatedBy.ShouldBe("operator");

        var audit = await CapturedAuditAsync();
        audit.BeforeData.ShouldNotBeNull().ShouldContain("\"status\":\"REMOVED\"");
        audit.AfterData.ShouldNotBeNull().ShouldContain("\"status\":\"ACTIVE\"");
    }

    [Fact]
    public async Task AFailedAuditWriteDoesNotFailTheAddItDescribes()
    {
        ActiveConsumer(4);
        _auditLog.AppendAsync(Arg.Any<UserSvc.Domain.Iam.IamAuditLog>(), Arg.Any<CancellationToken>())
            .Throws(new InvalidOperationException("audit table is unreachable"));

        await Sut.AddAsync(Caller(), 4, CancellationToken.None);

        _added.ShouldHaveSingleItem();
    }

    // ---------------------------------------------------------------- removing

    [Fact]
    public async Task RemovingAnIdThatIsNotOnTheListSucceedsAndRecordsNothing()
    {
        await Sut.RemoveAsync(Caller(), 4, CancellationToken.None);

        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());
        await _auditLog.DidNotReceive().AppendAsync(
            Arg.Any<UserSvc.Domain.Iam.IamAuditLog>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RemoveRetiresTheEntryWithoutCheckingWhetherTheAccountStillExists()
    {
        var existing = Entry(4, TestWhitelistStatuses.Active);
        _whitelist.FindAsync(4, Arg.Any<CancellationToken>()).Returns(existing);

        await Sut.RemoveAsync(Caller(), 4, CancellationToken.None);

        existing.Status.ShouldBe(TestWhitelistStatuses.Removed);
        existing.UpdatedAt.ShouldBe(Now);

        // An id whose account is gone is exactly the entry an operator most needs to delete, so the
        // consumer table is deliberately not consulted here.
        await _users.DidNotReceive().FindByIdAsync(Arg.Any<int>(), Arg.Any<CancellationToken>());

        var audit = await CapturedAuditAsync();
        audit.Action.ShouldBe(TestWhitelistAuditVocabulary.RemoveAction);
        audit.BeforeData.ShouldNotBeNull().ShouldContain("\"status\":\"ACTIVE\"");
        audit.AfterData.ShouldNotBeNull().ShouldContain("\"status\":\"REMOVED\"");
    }

    // ---------------------------------------------------------------- the hot read

    [Fact]
    public async Task IsTestUserAnswersFalseForANonPositiveIdWithoutTouchingTheStore()
    {
        (await Sut.IsTestUserAsync(0, CancellationToken.None)).ShouldBeFalse();

        await _whitelist.DidNotReceive().IsWhitelistedAsync(
            Arg.Any<int>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task IsTestUserFailsClosedWhenTheStoreCannotBeRead()
    {
        _whitelist.IsWhitelistedAsync(4, Arg.Any<CancellationToken>())
            .Throws(new InvalidOperationException("the database is down"));

        // It runs inside token validation, so any error it could hand back is one the caller could
        // propagate - turning a whitelist hiccup into a platform-wide authentication failure. False
        // hides test products, which is the safe direction.
        (await Sut.IsTestUserAsync(4, CancellationToken.None)).ShouldBeFalse();
    }

    [Fact]
    public async Task IsTestUserStillPropagatesCancellation()
    {
        _whitelist.IsWhitelistedAsync(4, Arg.Any<CancellationToken>())
            .Throws(new OperationCanceledException());

        // The caller gave up on the request; that is not a degraded read and must not be reported
        // as "not a test user".
        await Should.ThrowAsync<OperationCanceledException>(() =>
            Sut.IsTestUserAsync(4, CancellationToken.None));
    }

    [Fact]
    public async Task IsTestUserAnswersTheStore()
    {
        _whitelist.IsWhitelistedAsync(4, Arg.Any<CancellationToken>()).Returns(true);

        (await Sut.IsTestUserAsync(4, CancellationToken.None)).ShouldBeTrue();
    }

    // ---------------------------------------------------------------- helpers

    private static WhitelistCaller Caller() => new() { UserId = SuperAdminId };

    private static WhitelistCaller OrdinaryCaller() => new() { UserId = 42 };

    private static TestWhitelistEntry Entry(int userId, string status) => new()
    {
        Id = 1,
        UserId = userId,
        Status = status,
        CreatedAt = Now.AddDays(-30),
        UpdatedAt = Now.AddDays(-30),
        CreatedBy = "someone",
        UpdatedBy = "someone",
    };

    private void ActiveConsumer(int userId) =>
        _users.FindByIdAsync(userId, Arg.Any<CancellationToken>())
            .Returns(new User { Id = userId, Status = UserStatuses.Active });

    private async Task<UserSvc.Domain.Iam.IamAuditLog> CapturedAuditAsync()
    {
        var calls = _auditLog.ReceivedCalls().ToList();
        calls.ShouldNotBeEmpty("an audited write must write its audit row");

        await Task.CompletedTask;

        return (UserSvc.Domain.Iam.IamAuditLog)calls[^1].GetArguments()[0]!;
    }
}

/// <summary>A back-office caller under test control. Its own type for the same reason the supplier
/// slice's is: a fake shared across slices is the one file a change to either would break for
/// both.</summary>
internal sealed class WhitelistCaller : IBackOfficeCaller
{
    public int UserId { get; init; }

    public string Nickname { get; init; } = "operator";

    public string ActType { get; init; } = ActTypes.Platform;

    public string ActCode { get; init; } = string.Empty;

    public string ActDim { get; init; } = string.Empty;

    public string? IpAddress => "203.0.113.9";

    public string? RequestId => "req-whitelist-1";

    public EffectiveAuthz Authz { get; init; } = EffectiveAuthz.Empty;
}
