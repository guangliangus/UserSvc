using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;
using Xunit;
using static UserSvc.UnitTests.Tenancy.TenantTestData;

namespace UserSvc.UnitTests.Tenancy;

/// <summary>
/// The three shell endpoints. The derivation itself is covered next door; what matters here is the
/// order of the gates in front of it, and the three-state authority surface the shell reads.
/// </summary>
public sealed class BackOfficeContextAppServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 2, 9, 0, 0, TimeSpan.Zero);

    private readonly ITenantMemberRepository _members = Substitute.For<ITenantMemberRepository>();
    private readonly IUserTenantRoleRepository _bindings = Substitute.For<IUserTenantRoleRepository>();
    private readonly IRoleDirectory _roles = Substitute.For<IRoleDirectory>();
    private readonly IRbacCatalog _catalog = Substitute.For<IRbacCatalog>();
    private readonly IAdminStandingService _standing = Substitute.For<IAdminStandingService>();
    private readonly IBackOfficeAccountDirectory _accounts = Substitute.For<IBackOfficeAccountDirectory>();
    private readonly ISupplierCompanyLinkDirectory _links = Substitute.For<ISupplierCompanyLinkDirectory>();
    private readonly ITenantMasterDataDirectory _masterData =
        Substitute.For<ITenantMasterDataDirectory>();
    private readonly IIamAuditLog _audit = Substitute.For<IIamAuditLog>();
    private readonly IAuthzSnapshotProvider _snapshots = Substitute.For<IAuthzSnapshotProvider>();
    private readonly TestClock _clock = new(Now);
    private readonly List<IamAuditEntry> _auditTrail = [];

    public BackOfficeContextAppServiceTests()
    {
        _accounts.FindAsync(Arg.Any<int>(), Arg.Any<CancellationToken>()).Returns(Account());
        _members.ListActiveByUserAsync(Arg.Any<int>(), Arg.Any<CancellationToken>()).Returns([]);
        _catalog.ListActiveMenusAsync(Arg.Any<CancellationToken>()).Returns([]);
        _catalog.ListMenuIdsByRolesAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _catalog.ListPermissionsByRolesAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _links.ListSupplierCodesByCompanyAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _masterData.ValidateAsync(
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<CancellationToken>())
            .Returns([]);
        _audit.WriteAsync(Arg.Do<IamAuditEntry>(_auditTrail.Add), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);
    }

    private TenantContextAppService Contexts =>
        new(_members, _bindings, _roles, _catalog, _standing, _accounts, _links);

    private BackOfficeContextAppService Sut => new(
        Contexts,
        _members,
        _accounts,
        _masterData,
        _audit,
        _clock,
        NullLogger<BackOfficeContextAppService>.Instance,
        _snapshots);

    private BackOfficeContextAppService SutWithoutSnapshots => new(
        Contexts,
        _members,
        _accounts,
        _masterData,
        _audit,
        _clock,
        NullLogger<BackOfficeContextAppService>.Instance);

    // ------------------------------------------------------------------ selecting one

    [Fact]
    public async Task ChoosingATenantYouDoNotBelongToIsRefused()
    {
        _members.FindByUserAndTenantAsync(42, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns((TenantMember?)null);

        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.SelectContextAsync(
            PreTenantCaller(),
            new SelectTenantContextRequest { TenantType = TenantTypes.Company, TenantCode = "C1" },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.TenantNotAuthorized);
    }

    [Fact]
    public async Task ASuspendedMembershipSaysSoRatherThanDenyingItExists()
    {
        _members.FindByUserAndTenantAsync(42, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns(Member(userId: 42, status: TenantMemberStatuses.Disabled));

        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.SelectContextAsync(
            PreTenantCaller(),
            new SelectTenantContextRequest { TenantType = TenantTypes.Company, TenantCode = "C1" },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.TenantDisabled);
    }

    [Fact]
    public async Task AWholeDimensionRowIsNotSelectableByItsSentinelCode()
    {
        // Defensive: the sentinel branches away before this. Reaching computeTenant with "*" would
        // treat it as a real tenant code.
        _members.FindByUserAndTenantAsync(42, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns(Member(userId: 42, scopeAll: true));

        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.SelectContextAsync(
            PreTenantCaller(),
            new SelectTenantContextRequest { TenantType = TenantTypes.Company, TenantCode = "C1" },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.TenantNotAuthorized);
    }

    [Fact]
    public async Task ADisabledAccountCannotKeepRe_enteringContexts()
    {
        // A member row says nothing about the account, and this endpoint hands out a fresh
        // authority surface every time it is called.
        _members.FindByUserAndTenantAsync(42, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns(Member(userId: 42));
        _accounts.FindAsync(42, Arg.Any<CancellationToken>())
            .Returns(Account(id: 42, status: BackOfficeAccountStates.Disabled));

        var ex = await Should.ThrowAsync<UnauthorizedException>(() => Sut.SelectContextAsync(
            PreTenantCaller(),
            new SelectTenantContextRequest { TenantType = TenantTypes.Company, TenantCode = "C1" },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.AccountDisabled);
        ex.StatusCode.ShouldBe(401);
        _auditTrail.ShouldBeEmpty();
    }

    [Fact]
    public async Task ATenantThatTheMasterDataHasSwitchedOffCannotBeEntered()
    {
        _members.FindByUserAndTenantAsync(42, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns(Member(userId: 42));
        _masterData.ValidateAsync(
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<CancellationToken>())
            .Returns([new TenantMasterDataEntry(TenantTypes.Company, "C1", Usable: false,
                new Dictionary<string, string>())]);

        var ex = await Should.ThrowAsync<ConflictException>(() => Sut.SelectContextAsync(
            PreTenantCaller(),
            new SelectTenantContextRequest { TenantType = TenantTypes.Company, TenantCode = "C1" },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.TenantInactive);
        _auditTrail.ShouldBeEmpty("the refusal happens before anything is recorded");
    }

    [Fact]
    public async Task AMasterDataOutageDoesNotLockEverybodyOutOfEveryTenant()
    {
        // Fail open, deliberately: this gate keeps people out of a switched-off tenant, and the
        // authorization boundary is the member row plus the permission codes.
        _members.FindByUserAndTenantAsync(42, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns(Member(userId: 42));
        _masterData.ValidateAsync(
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<CancellationToken>())
            .Returns((IReadOnlyList<TenantMasterDataEntry>?)null);

        var result = await Sut.SelectContextAsync(
            PreTenantCaller(),
            new SelectTenantContextRequest { TenantType = TenantTypes.Company, TenantCode = "C1" },
            CancellationToken.None);

        result.ActiveTenant!.CompanyCode.ShouldBe("C1");
    }

    [Fact]
    public async Task EnteringATenantIsAuditedAndUpdatesTheLastLogin()
    {
        _members.FindByUserAndTenantAsync(42, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns(Member(userId: 42, isAdmin: true));

        var result = await Sut.SelectContextAsync(
            PreTenantCaller(),
            new SelectTenantContextRequest { TenantType = TenantTypes.Company, TenantCode = "C1" },
            CancellationToken.None);

        result.IsTenantAdmin.ShouldBeTrue();
        result.ActiveTenant!.Type.ShouldBe("company");
        result.Scopes[TenantTypes.Company].Values.ShouldBe(["C1"]);

        var audit = _auditTrail.ShouldHaveSingleItem();
        audit.Action.ShouldBe(IamAuditActions.TenantSwitch);
        audit.TenantCode.ShouldBe("C1");
        await _accounts.Received(1).TouchLastLoginAsync(42, Now, Arg.Any<CancellationToken>());
    }

    // ------------------------------------------------------------ selecting a dimension

    [Fact]
    public async Task AWholeDimensionNeedsStandingAndIsNeverLookedUpAsAMembership()
    {
        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.SelectContextAsync(
            PreTenantCaller(),
            new SelectTenantContextRequest
            {
                TenantType = TenantTypes.Supplier,
                TenantCode = TenantScopes.ScopeAllSentinelCode,
            },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.TenantNotAuthorized);
        await _members.DidNotReceive().FindByUserAndTenantAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task EnteringAWholeDimensionCarriesNoAdministratorSeatAndNoMasterDataCheck()
    {
        _members.ListActiveByUserAsync(42, Arg.Any<CancellationToken>())
            .Returns([Member(id: 1, userId: 42, tenantType: TenantTypes.Supplier, scopeAll: true,
                tenantCode: TenantScopes.ScopeAllSentinelCode, isAdmin: true)]);

        var result = await Sut.SelectContextAsync(
            PreTenantCaller(),
            new SelectTenantContextRequest
            {
                TenantType = TenantTypes.Supplier,
                TenantCode = TenantScopes.ScopeAllSentinelCode,
            },
            CancellationToken.None);

        result.ActiveTenant!.Type.ShouldBe("global");
        result.ActiveTenant.Dimension.ShouldBe(TenantTypes.Supplier);
        result.IsTenantAdmin.ShouldBeFalse("a dimension has no administrator seat");
        result.Scopes[TenantTypes.Supplier].IsGlobal.ShouldBeTrue();
        result.Scopes[TenantTypes.Company].IsGlobal.ShouldBeFalse();

        _auditTrail.ShouldHaveSingleItem().TenantCode.ShouldBe(
            TenantScopes.ScopeAllSentinelCode,
            "the trail says which side was entered rather than filing it under the platform");

        await _masterData.DidNotReceive().ValidateAsync(
            Arg.Any<IReadOnlyCollection<string>>(),
            Arg.Any<IReadOnlyCollection<string>>(),
            Arg.Any<CancellationToken>());
    }

    // -------------------------------------------------------------------- the chooser

    [Fact]
    public async Task TheChooserListsDimensionsFirstAndDropsTenantsNobodyCouldEnter()
    {
        _members.ListActiveByUserAsync(42, Arg.Any<CancellationToken>()).Returns(
        [
            Member(id: 1, userId: 42, scopeAll: true, tenantCode: TenantScopes.ScopeAllSentinelCode),
            Member(id: 2, userId: 42, tenantCode: "C1", isAdmin: true),
            Member(id: 3, userId: 42, tenantCode: "C2"),
        ]);
        _masterData.ValidateAsync(
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<CancellationToken>())
            .Returns(
            [
                new TenantMasterDataEntry(TenantTypes.Company, "C1", true,
                    new Dictionary<string, string> { ["zh-TW"] = "Sunshine" }),
                new TenantMasterDataEntry(TenantTypes.Company, "C2", false,
                    new Dictionary<string, string>()),
            ]);

        var result = await Sut.ListTenantsAsync(PreTenantCaller(), CancellationToken.None);

        result.IsGlobal.ShouldBeTrue();
        result.Tenants.Count.ShouldBe(2);
        result.Tenants[0].ScopeAll.ShouldBeTrue();
        result.Tenants[0].TenantCode.ShouldBe(TenantScopes.ScopeAllSentinelCode);
        result.Tenants[1].TenantCode.ShouldBe("C1");
        result.Tenants[1].IsAdmin.ShouldBeTrue();
        result.Tenants[1].TenantName!["zh-TW"].ShouldBe("Sunshine");
        result.Tenants.ShouldNotContain(
            tenant => tenant.TenantCode == "C2",
            "listing a tenant the select endpoint would refuse only produces dead rows");
    }

    // ------------------------------------------------------------------------- the shell

    [Fact]
    public async Task WithNoContextTheShellIsToldExplicitlyThatItHasNothing()
    {
        var result = await Sut.GetMeAsync(new BackOfficeCaller(42, "somebody", null), CancellationToken.None);

        result.Roles.ShouldNotBeNull().ShouldBeEmpty();
        result.Permissions.ShouldNotBeNull().ShouldBeEmpty();
        result.Menus.ShouldNotBeNull().ShouldBeEmpty();
        result.MenuRoutes.ShouldNotBeNull().ShouldBeEmpty();
        result.Scopes.ShouldNotBeNull();
        result.ActiveTenant.ShouldBeNull();
        result.IsTenantAdmin.ShouldBeFalse();
    }

    [Fact]
    public async Task TheShellReadsItsGrantsFromTheSnapshot()
    {
        _members.ListActiveByUserAsync(42, Arg.Any<CancellationToken>())
            .Returns([Member(id: 2, userId: 42, tenantCode: "C1", isAdmin: true)]);
        _snapshots.GetOrComputeAsync(
                42, Arg.Any<ActClaim>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(new AuthzSnapshot(
                ["finance"],
                ["order.read"],
                ["order"],
                new Dictionary<string, ScopeClaim>
                {
                    [TenantTypes.Company] = new(["C1"], false),
                    [TenantTypes.Supplier] = ScopeClaim.None,
                }));
        _snapshots.MenuRoutesForCodesAsync(
                Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([new MenuRoute("order", "/orders")]);

        var result = await Sut.GetMeAsync(
            new BackOfficeCaller(42, "somebody", new ActClaim(ActTypes.Company, "C1")),
            CancellationToken.None);

        result.Roles.ShouldBe(["finance"]);
        result.Menus.ShouldBe(["order"]);
        result.MenuRoutes!.ShouldHaveSingleItem().Path.ShouldBe("/orders");
        result.IsTenantAdmin.ShouldBeTrue();
        result.ActiveTenant!.CompanyCode.ShouldBe("C1");
        result.Origin.ShouldBe(BackOfficeAccountStates.ExternalOrigin);
    }

    [Fact]
    public async Task ASnapshotFailureLeavesTheGrantsUndeliveredRatherThanEmpty()
    {
        // This endpoint is the front end's resynchronisation source. Empty closes every gate; null
        // means "not this time" and leaves the session as it was. A hiccup must produce the second.
        _snapshots.GetOrComputeAsync(
                42, Arg.Any<ActClaim>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("redis is away"));

        var result = await Sut.GetMeAsync(
            new BackOfficeCaller(42, "somebody", new ActClaim(ActTypes.Company, "C1")),
            CancellationToken.None);

        result.Roles.ShouldBeNull();
        result.Permissions.ShouldBeNull();
        result.Menus.ShouldBeNull();
        result.MenuRoutes.ShouldBeNull();
        result.Scopes.ShouldBeNull();
        result.ActiveTenant!.CompanyCode.ShouldBe("C1", "the context itself still comes from the token");
    }

    [Fact]
    public async Task AShellWithNoSnapshotComponentWiredUpSaysUndeliveredToo()
    {
        var result = await SutWithoutSnapshots.GetMeAsync(
            new BackOfficeCaller(42, "somebody", new ActClaim(ActTypes.Company, "C1")),
            CancellationToken.None);

        result.Menus.ShouldBeNull();
    }

    /// <summary>A caller that has authenticated but not yet chosen a context.</summary>
    private static BackOfficeCaller PreTenantCaller() => new(42, "chooser", null);
}
