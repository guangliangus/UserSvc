using NSubstitute;
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
/// The derivation funnel. These cases are the derivation table: what a platform, a whole-dimension
/// and a tenant context each resolve to, and - just as load-bearing - what they must not resolve
/// to.
/// </summary>
public sealed class TenantContextAppServiceTests
{
    private readonly ITenantMemberRepository _members = Substitute.For<ITenantMemberRepository>();
    private readonly IUserTenantRoleRepository _bindings = Substitute.For<IUserTenantRoleRepository>();
    private readonly IRoleDirectory _roles = Substitute.For<IRoleDirectory>();
    private readonly IRbacCatalog _catalog = Substitute.For<IRbacCatalog>();
    private readonly IAdminStandingService _standing = Substitute.For<IAdminStandingService>();
    private readonly IBackOfficeAccountDirectory _accounts = Substitute.For<IBackOfficeAccountDirectory>();
    private readonly ISupplierCompanyLinkDirectory _links = Substitute.For<ISupplierCompanyLinkDirectory>();

    public TenantContextAppServiceTests()
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
    }

    private TenantContextAppService Sut =>
        new(_members, _bindings, _roles, _catalog, _standing, _accounts, _links);

    // ------------------------------------------------------------------ the account gate

    [Theory]
    [InlineData("PENDING", ActTypes.Platform, "")]
    [InlineData("PENDING", ActTypes.Global, TenantTypes.Company)]
    [InlineData("PENDING", ActTypes.Company, "C1")]
    [InlineData("DISABLED", ActTypes.Supplier, "S1")]
    [InlineData("DISABLED", ActTypes.Global, "")]
    public async Task AnAccountThatIsNotActiveCarriesNoAuthorityInAnyContext(
        string status, string actType, string codeOrDimension)
    {
        // Empty rather than an error: an error would bounce the caller to the sign-in page, and an
        // account still being onboarded should not have to sign in again once it is finished. And
        // empty means empty lists, because a missing menu list reads as "this build does not gate".
        _accounts.FindAsync(7, Arg.Any<CancellationToken>()).Returns(Account(id: 7, status: status));

        var act = actType == ActTypes.Global
            ? new ActClaim(actType, Dimension: codeOrDimension)
            : new ActClaim(actType, codeOrDimension);

        var result = await Sut.ComputeAsync(7, act, CancellationToken.None);

        result.Act.ShouldBeNull();
        result.Roles.ShouldBeEmpty();
        result.Permissions.ShouldBeEmpty();
        result.Menus.ShouldNotBeNull().ShouldBeEmpty();
        result.Scopes[TenantTypes.Company].IsGlobal.ShouldBeFalse();
        result.Scopes[TenantTypes.Supplier].Values.ShouldBeEmpty();

        // Nothing about memberships, roles or the catalogue is even read.
        await _members.DidNotReceive().ListActiveByUserAsync(
            Arg.Any<int>(), Arg.Any<CancellationToken>());
        await _catalog.DidNotReceive().ListActiveMenusAsync(Arg.Any<CancellationToken>());
    }

    // ---------------------------------------------------------------------- platform

    [Fact]
    public async Task ThePlatformContextGrantsEveryActiveMenuAndPermission()
    {
        _standing.IsPlatformSuperAdminAsync(1, Arg.Any<CancellationToken>()).Returns(true);
        _catalog.ListActiveMenusAsync(Arg.Any<CancellationToken>())
            .Returns([Menu(1, "order"), Menu(2, "dashboard")]);
        _catalog.ListActivePermissionCodesAsync(Arg.Any<CancellationToken>()).Returns(["p2", "p1"]);

        var result = await Sut.ComputeAsync(
            1, new ActClaim(ActTypes.Platform), CancellationToken.None);

        result.Act!.Type.ShouldBe(ActTypes.Platform);
        result.Menus.ShouldBe(["dashboard", "order"]);
        result.Permissions.ShouldBe(["p1", "p2"]);
        result.Roles.ShouldBeEmpty("the flag is not a role binding");
        result.Scopes[TenantTypes.Company].IsGlobal.ShouldBeTrue();
        result.Scopes[TenantTypes.Supplier].IsGlobal.ShouldBeTrue();
    }

    [Fact]
    public async Task APlatformClaimIsWorthlessOnceTheFlagIsGone()
    {
        // The standing is re-read; the presented claim is never trusted.
        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.ComputeAsync(
            1, new ActClaim(ActTypes.Platform), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.TenantNotAuthorized);
    }

    [Fact]
    public async Task AWholeDimensionRowIsNeverResolvedAsATenantContext()
    {
        // The selection endpoint guards this too, but three other paths - refresh, the per-request
        // snapshot and a re-derivation after a role change - reach the funnel with an act claim
        // read straight off a token. An act of {COMPANY, "*"} matches the scope-all row on the
        // unique key, and without this guard the derivation would treat the sentinel as a real
        // tenant code and put it in the data-scope envelope.
        _members.FindByUserAndTenantAsync(
                7, TenantTypes.Company, TenantScopes.ScopeAllSentinelCode, Arg.Any<CancellationToken>())
            .Returns(Member(userId: 7, scopeAll: true, tenantCode: TenantScopes.ScopeAllSentinelCode));

        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.ComputeAsync(
            7,
            new ActClaim(ActTypes.Company, TenantScopes.ScopeAllSentinelCode),
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.TenantNotAuthorized);

        // Refused before anything was derived from it.
        await _links.DidNotReceiveWithAnyArgs()
            .ListSupplierCodesByCompanyAsync(default!, default);
    }

    // ------------------------------------------------------------------ whole dimension

    [Fact]
    public async Task ASuperAdministratorOnTheGlobalPathStillGetsEverything()
    {
        _standing.IsPlatformSuperAdminAsync(1, Arg.Any<CancellationToken>()).Returns(true);
        _members.ListActiveByUserAsync(1, Arg.Any<CancellationToken>()).Returns(
        [
            Member(id: 1, userId: 1, scopeAll: true, tenantCode: TenantScopes.ScopeAllSentinelCode),
            Member(id: 2, userId: 1, tenantType: TenantTypes.Supplier, scopeAll: true,
                tenantCode: TenantScopes.ScopeAllSentinelCode),
        ]);
        _catalog.ListActiveMenusAsync(Arg.Any<CancellationToken>())
            .Returns([Menu(1, "order"), Menu(2, "dashboard")]);
        _catalog.ListActivePermissionCodesAsync(Arg.Any<CancellationToken>()).Returns(["p1", "p2"]);

        var result = await Sut.ComputeAsync(
            1, new ActClaim(ActTypes.Global), CancellationToken.None);

        result.Menus.ShouldBe(["dashboard", "order"]);
        result.Permissions.ShouldBe(["p1", "p2"]);
        result.Scopes[TenantTypes.Company].IsGlobal.ShouldBeTrue();
        result.Scopes[TenantTypes.Supplier].IsGlobal.ShouldBeTrue();
    }

    [Fact]
    public async Task AGlobalOperatorGetsOnlyWhatItsOwnRolesGrant()
    {
        // The full-access short circuit reads the whole permission catalogue. If this test ever
        // touches that call, somebody has widened a non-administrator into an administrator.
        _members.ListActiveByUserAsync(7, Arg.Any<CancellationToken>()).Returns(
        [
            Member(id: 1, userId: 7, scopeAll: true, tenantCode: TenantScopes.ScopeAllSentinelCode),
            Member(id: 2, userId: 7, tenantType: TenantTypes.Supplier, scopeAll: true,
                tenantCode: TenantScopes.ScopeAllSentinelCode),
        ]);
        _bindings.ListRoleIdsByMemberIdsAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(new Dictionary<int, IReadOnlyList<int>> { [1] = [5], [2] = [6] });
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Role(5, "company_ops"), Role(6, "supplier_ops")]);
        _catalog.ListActiveMenusAsync(Arg.Any<CancellationToken>())
            .Returns([Menu(1, "order"), Menu(2, "supplier_products", audience: TenantTypes.Supplier)]);
        _catalog.ListMenuIdsByRolesAsync(
                Arg.Is<IReadOnlyCollection<int>>(ids => ids.Contains(5)), Arg.Any<CancellationToken>())
            .Returns([1]);
        _catalog.ListMenuIdsByRolesAsync(
                Arg.Is<IReadOnlyCollection<int>>(ids => ids.Contains(6)), Arg.Any<CancellationToken>())
            .Returns([2]);
        _catalog.ListPermissionsByRolesAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Permission(1, "order.read", 1), Permission(2, "supplier.read", 2)]);

        var result = await Sut.ComputeAsync(7, new ActClaim(ActTypes.Global), CancellationToken.None);

        result.Roles.ShouldBe(["company_ops", "supplier_ops"]);
        result.Roles.ShouldNotContain("admin", "breadth is not power");
        result.Menus.ShouldBe(["order", "supplier_products"]);
        result.Permissions.ShouldBe(["order.read", "supplier.read"]);
        result.Scopes[TenantTypes.Company].IsGlobal.ShouldBeTrue();
        result.Scopes[TenantTypes.Supplier].IsGlobal.ShouldBeTrue();

        await _catalog.DidNotReceive().ListActivePermissionCodesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ChoosingOneDimensionLeavesNoBreadthOnTheOther()
    {
        // The isolation the sign-in choice buys: inside "all companies" there is no supplier
        // breadth at all, so a scope-filtered query returns nothing rather than the whole platform.
        _members.ListActiveByUserAsync(7, Arg.Any<CancellationToken>()).Returns(
        [
            Member(id: 1, userId: 7, scopeAll: true, tenantCode: TenantScopes.ScopeAllSentinelCode),
            Member(id: 2, userId: 7, tenantType: TenantTypes.Supplier, tenantCode: "S1"),
        ]);

        var result = await Sut.ComputeAsync(
            7, new ActClaim(ActTypes.Global, Dimension: TenantTypes.Company), CancellationToken.None);

        result.Act!.Dimension.ShouldBe(TenantTypes.Company);
        result.Scopes[TenantTypes.Company].IsGlobal.ShouldBeTrue();
        result.Scopes[TenantTypes.Supplier].IsGlobal.ShouldBeFalse();
        result.Scopes[TenantTypes.Supplier].Values.ShouldBeEmpty(
            "a specific supplier code must not leak into an envelope governed by global roles");
    }

    [Fact]
    public async Task OnlyTheChosenDimensionsRowsContributeRoles()
    {
        _members.ListActiveByUserAsync(7, Arg.Any<CancellationToken>()).Returns(
        [
            Member(id: 1, userId: 7, scopeAll: true, tenantCode: TenantScopes.ScopeAllSentinelCode),
            Member(id: 2, userId: 7, tenantType: TenantTypes.Supplier, scopeAll: true,
                tenantCode: TenantScopes.ScopeAllSentinelCode),
        ]);
        _bindings.ListRoleIdsByMemberIdsAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(new Dictionary<int, IReadOnlyList<int>> { [2] = [6] });
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Role(6, "supplier_ops", category: RoleCategories.Supplier)]);

        var result = await Sut.ComputeAsync(
            7, new ActClaim(ActTypes.Global, Dimension: TenantTypes.Supplier), CancellationToken.None);

        result.Roles.ShouldBe(["supplier_ops"]);
        await _bindings.Received(1).ListRoleIdsByMemberIdsAsync(
            Arg.Is<IReadOnlyCollection<int>>(ids => ids.Count == 1 && ids.Contains(2)),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task APermissionWhoseMenuWasDeactivatedFallsWithIt()
    {
        _members.ListActiveByUserAsync(7, Arg.Any<CancellationToken>())
            .Returns([Member(id: 1, userId: 7, scopeAll: true,
                tenantCode: TenantScopes.ScopeAllSentinelCode)]);
        _bindings.ListRoleIdsByMemberIdsAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(new Dictionary<int, IReadOnlyList<int>> { [1] = [5] });
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Role(5, "ops")]);

        // Menu 2 was granted but is no longer active.
        _catalog.ListMenuIdsByRolesAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([1, 2]);
        _catalog.ListActiveMenusAsync(Arg.Any<CancellationToken>()).Returns([Menu(1, "order")]);
        _catalog.ListPermissionsByRolesAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(
            [
                Permission(1, "order.read", 1),
                Permission(2, "order.legacy", 2),
                Permission(3, "audit.read"),
            ]);

        var result = await Sut.ComputeAsync(7, new ActClaim(ActTypes.Global), CancellationToken.None);

        result.Menus.ShouldBe(["order"]);
        result.Permissions.ShouldBe(
            ["audit.read", "order.read"],
            "the dead menu takes its permission with it; a menu-less point has no menu to lose");
    }

    // --------------------------------------------------------------------- one tenant

    [Fact]
    public async Task ACompanyContextSeesItselfAndEverySupplierMountedOnIt()
    {
        _members.FindByUserAndTenantAsync(57, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns(Member(isAdmin: true));
        _bindings.ListByMemberIdAsync(900, Arg.Any<CancellationToken>())
            .Returns([new UserTenantRole { MemberId = 900, RoleId = 10 }]);
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Role(10, "company_admin", isAdmin: true)]);
        _links.ListSupplierCodesByCompanyAsync("C1", Arg.Any<CancellationToken>())
            .Returns(["S2", "S1"]);
        _catalog.ListMenuIdsByRolesAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([1]);
        _catalog.ListActiveMenusAsync(Arg.Any<CancellationToken>()).Returns([Menu(1, "order")]);
        _catalog.ListPermissionsByRolesAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Permission(1, "order.read", 1), Permission(2, "uam.member.read")]);

        var result = await Sut.ComputeAsync(
            57, new ActClaim(ActTypes.Company, "C1"), CancellationToken.None);

        result.Act!.IsAdmin.ShouldBeTrue("the shell renders its administrator affordances from this");
        result.Scopes[TenantTypes.Company].Values.ShouldBe(["C1"]);
        result.Scopes[TenantTypes.Supplier].Values.ShouldBe(["S1", "S2"]);
        result.Permissions.ShouldBe(["order.read", "uam.member.read"]);

        // Once for the whole role set, once for the SYSTEM subset - that second call is what
        // decides whether a menu-less permission point may be granted at all.
        await _catalog.Received(2).ListPermissionsByRolesAsync(
            Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ATenantsOwnRoleCannotCarryAServiceLevelPermission()
    {
        _members.FindByUserAndTenantAsync(57, TenantTypes.Supplier, "S9", Arg.Any<CancellationToken>())
            .Returns(Member(tenantType: TenantTypes.Supplier, tenantCode: "S9"));
        _bindings.ListByMemberIdAsync(900, Arg.Any<CancellationToken>())
            .Returns([new UserTenantRole { MemberId = 900, RoleId = 20 }]);
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Role(20, "supplier_pm", category: RoleCategories.Supplier,
                ownerType: RoleOwnerTypes.Supplier)]);
        _links.FindCompanyCodeBySupplierAsync("S9", Arg.Any<CancellationToken>()).Returns("C9");
        _catalog.ListMenuIdsByRolesAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([1]);
        _catalog.ListActiveMenusAsync(Arg.Any<CancellationToken>())
            .Returns([Menu(1, "supplier_orders", audience: TenantTypes.Supplier)]);
        _catalog.ListPermissionsByRolesAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Permission(1, "supplier_orders.read", 1), Permission(2, "svc.internal")]);

        var result = await Sut.ComputeAsync(
            57, new ActClaim(ActTypes.Supplier, "S9"), CancellationToken.None);

        result.Scopes[TenantTypes.Supplier].Values.ShouldBe(["S9"]);
        result.Scopes[TenantTypes.Company].Values.ShouldBe(["C9"], "the mounted company comes along");
        result.Permissions.ShouldBe(["supplier_orders.read"]);

        // The role is not a SYSTEM role, so the second lookup never happens - and without it the
        // menu-less point has nothing that could have granted it.
        await _catalog.Received(1).ListPermissionsByRolesAsync(
            Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnIndependentSupplierGetsAnEmptyCompanyScopeRatherThanAnError()
    {
        _members.FindByUserAndTenantAsync(57, TenantTypes.Supplier, "S9", Arg.Any<CancellationToken>())
            .Returns(Member(tenantType: TenantTypes.Supplier, tenantCode: "S9"));
        _bindings.ListByMemberIdAsync(900, Arg.Any<CancellationToken>()).Returns([]);
        _links.FindCompanyCodeBySupplierAsync("S9", Arg.Any<CancellationToken>()).Returns((string?)null);

        var result = await Sut.ComputeAsync(
            57, new ActClaim(ActTypes.Supplier, "S9"), CancellationToken.None);

        result.Scopes[TenantTypes.Company].Values.ShouldBeEmpty();
        result.Scopes[TenantTypes.Company].IsGlobal.ShouldBeFalse("empty is not unrestricted");
        result.Menus.ShouldBeEmpty();
        result.Permissions.ShouldBeEmpty();
    }

    [Fact]
    public async Task AMembershipThatIsNotActiveCarriesNoContext()
    {
        _members.FindByUserAndTenantAsync(57, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns(Member(status: TenantMemberStatuses.Disabled));

        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.ComputeAsync(
            57, new ActClaim(ActTypes.Company, "C1"), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.TenantNotAuthorized);
    }

    [Fact]
    public async Task ASuperAdministratorKeepsEveryPermissionInsideATenantContext()
    {
        // Reachable whenever they are also an ordinary member somewhere. Deriving purely from that
        // membership would strip them down while every service-layer guard still says otherwise.
        _standing.IsPlatformSuperAdminAsync(57, Arg.Any<CancellationToken>()).Returns(true);
        _members.FindByUserAndTenantAsync(57, TenantTypes.Company, "C001", Arg.Any<CancellationToken>())
            .Returns(Member(tenantCode: "C001"));
        _bindings.ListByMemberIdAsync(900, Arg.Any<CancellationToken>())
            .Returns([new UserTenantRole { MemberId = 900, RoleId = 30 }]);
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Role(30, "sales")]);
        _catalog.ListActiveMenusAsync(Arg.Any<CancellationToken>())
            .Returns([Menu(1, "order"), Menu(2, "user-suppliers", audience: "platform")]);
        _catalog.ListActivePermissionCodesAsync(Arg.Any<CancellationToken>())
            .Returns(["order.read", "uam.role.manage"]);

        var result = await Sut.ComputeAsync(
            57, new ActClaim(ActTypes.Company, "C001"), CancellationToken.None);

        result.Permissions.ShouldBe(["order.read", "uam.role.manage"]);
        result.Menus.ShouldBe(["order", "user-suppliers"]);
    }

    // ----------------------------------------------------------------- global standing

    [Fact]
    public async Task WholeDimensionAccessIsWhatMakesSomebodyGlobal()
    {
        _members.ListActiveByUserAsync(7, Arg.Any<CancellationToken>())
            .Returns([Member(id: 1, userId: 7, scopeAll: true,
                tenantCode: TenantScopes.ScopeAllSentinelCode)]);

        (await Sut.IsGlobalUserAsync(7, CancellationToken.None)).ShouldBeTrue();
    }

    [Fact]
    public async Task SpecificMembershipsDoNotMakeSomebodyGlobal()
    {
        _members.ListActiveByUserAsync(7, Arg.Any<CancellationToken>())
            .Returns([Member(id: 1, userId: 7, tenantCode: "C1")]);

        (await Sut.IsGlobalUserAsync(7, CancellationToken.None)).ShouldBeFalse();
    }

    [Fact]
    public async Task TheSuperAdministratorFlagCountsAsBothDimensions()
    {
        _standing.IsPlatformSuperAdminAsync(1, Arg.Any<CancellationToken>()).Returns(true);

        (await Sut.IsGlobalUserAsync(1, CancellationToken.None)).ShouldBeTrue();
    }

    [Fact]
    public async Task GlobalDimensionsListsOnlyWholeDimensionRowsInAFixedOrder()
    {
        _members.ListActiveByUserAsync(7, Arg.Any<CancellationToken>()).Returns(
        [
            Member(id: 1, userId: 7, tenantType: TenantTypes.Supplier, scopeAll: true,
                tenantCode: TenantScopes.ScopeAllSentinelCode),
            Member(id: 2, userId: 7, scopeAll: true, tenantCode: TenantScopes.ScopeAllSentinelCode),
            Member(id: 3, userId: 7, tenantCode: "C1"),
        ]);

        var dimensions = await Sut.GlobalDimensionsAsync(7, CancellationToken.None);

        dimensions.ShouldBe(
            [TenantTypes.Company, TenantTypes.Supplier],
            "the chooser and the switcher have to list them the same way round");
    }

    [Fact]
    public async Task ThePlatformSuperAdministratorIsNotOfferedDimensionsToChooseBetween()
    {
        // They act as PLATFORM, reach both dimensions and choose nothing; two cards would be shown
        // to the one person with nothing to pick.
        _standing.IsPlatformSuperAdminAsync(1, Arg.Any<CancellationToken>()).Returns(true);

        (await Sut.GlobalDimensionsAsync(1, CancellationToken.None)).ShouldBeEmpty();
    }
}
