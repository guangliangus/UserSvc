using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;
using Xunit;

namespace UserSvc.UnitTests.Iam;

/// <summary>
/// The gates. These are the tests that matter most in this module: every one of them describes a way
/// somebody could otherwise be let through.
/// </summary>
public sealed class AdminScopeServiceTests
{
    private readonly IBackOfficeUserDirectory _users = Substitute.For<IBackOfficeUserDirectory>();
    private readonly ITenantMemberDirectory _members = Substitute.For<ITenantMemberDirectory>();
    private readonly IUserTenantRoleRepository _bindings = Substitute.For<IUserTenantRoleRepository>();
    private readonly IRoleRepository _roles = Substitute.For<IRoleRepository>();
    private readonly IRoleMenuRepository _roleMenus = Substitute.For<IRoleMenuRepository>();
    private readonly IMenuRepository _menus = Substitute.For<IMenuRepository>();
    private readonly IRolePermissionRepository _rolePermissions = Substitute.For<IRolePermissionRepository>();

    private AdminScopeService Sut =>
        new(_users, _members, _bindings, _roles, _roleMenus, _menus, _rolePermissions);

    [Fact]
    public async Task SuperAdminStandingIsDecidedBeforeAnyMembershipIsRead()
    {
        var caller = new FakeCaller { UserId = 1 };
        Flags(1, isSuperAdmin: true);

        var scope = await Sut.ResolveAdminScopeAsync(caller, CancellationToken.None);

        scope.IsSuperAdmin.ShouldBeTrue();
        scope.Owners.Single().OwnerType.ShouldBe(RoleOwnerTypes.System);
        // The flag holds with zero memberships, so resolution must short-circuit before reading any.
        await _members.DidNotReceive().ListActiveByUserAsync(
            Arg.Any<int>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnAbsentCallerAdministersNothing()
    {
        var scope = await Sut.ResolveAdminScopeAsync(new FakeCaller { UserId = 0 }, CancellationToken.None);

        scope.IsSuperAdmin.ShouldBeFalse();
        scope.Owners.ShouldBeEmpty();
    }

    [Fact]
    public async Task AWholeDimensionMembershipGrantsStandingButNotRoleOwnership()
    {
        var caller = new FakeCaller { UserId = 5 };
        Flags(5, isSuperAdmin: false);

        var admin = Fixtures.Role(90, "company_admin", isAdmin: true);
        var global = Fixtures.Membership(1, 5, tenantCode: IamConstants.ScopeAllSentinelCode, scopeAll: true);
        Memberships(5, global);
        Bindings(new Dictionary<int, IReadOnlyList<int>> { [1] = [90] });
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([admin]);

        var scope = await Sut.ResolveAdminScopeAsync(caller, CancellationToken.None);

        scope.AdminRoles.ShouldHaveSingleItem();
        scope.Owners.ShouldBeEmpty("a whole-dimension row owns no tenant, so it cannot own a role");
        scope.AdminTenants.ShouldBeEmpty();
        scope.AdminRolesForOwner(new RoleOwner(RoleOwnerTypes.Company, "C7"))
            .ShouldHaveSingleItem("the sentinel key answers for every tenant of that dimension");
    }

    [Fact]
    public async Task AGlobalSessionThatChoseOneDimensionAdministersOnlyThatSide()
    {
        var caller = FakeCaller.Global(5, TenantTypes.Company);
        Flags(5, isSuperAdmin: false);

        var companyAdmin = Fixtures.Role(90, "company_admin", isAdmin: true);
        var supplierAdmin = Fixtures.Role(91, "supplier_admin", isAdmin: true);

        Memberships(
            5,
            Fixtures.Membership(1, 5, TenantTypes.Company, "C1"),
            Fixtures.Membership(2, 5, TenantTypes.Supplier, "S1"));

        Bindings(new Dictionary<int, IReadOnlyList<int>> { [1] = [90], [2] = [91] });
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([companyAdmin, supplierAdmin]);

        var scope = await Sut.ResolveAdminScopeAsync(caller, CancellationToken.None);

        scope.Owners.Select(owner => owner.OwnerType).ShouldBe([RoleOwnerTypes.Company]);
        scope.AdminTenants.Select(owner => owner.Code).ShouldBe(["C1"]);
        scope.AdminRoles.Count.ShouldBe(
            2, "AdminRoles lists what the person holds; the dimension lock narrows the per-owner map");
    }

    [Fact]
    public async Task TheRoleGateNeedsTheRolesMenuAndTheRolePointOnTheSameRole()
    {
        _roleMenus.ListMenuIdsByRoleIdsAsync(
                Arg.Is<IReadOnlyCollection<int>>(ids => ids.Contains(90)), Arg.Any<CancellationToken>())
            .Returns([19]);

        _menus.ListByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Menu(19, IamConstants.MenuCodeUserRoles)]);

        _rolePermissions.ListPermissionsByRoleIdsAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Permission(1, "uam.member.manage")]);

        var gated = await Sut.RoleCarriesRoleManageGateAsync(90, CancellationToken.None);

        gated.ShouldBeFalse("the roles menu alone makes a member administrator, not a role administrator");
    }

    [Fact]
    public async Task TheRoleGateRefusesAnInactivePermissionPoint()
    {
        _roleMenus.ListMenuIdsByRoleIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([19]);
        _menus.ListByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Menu(19, IamConstants.MenuCodeUserRoles)]);
        _rolePermissions.ListPermissionsByRoleIdsAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Permission(
                1, IamConstants.PermissionCodeRoleManage, status: PermissionStatuses.Inactive)]);

        (await Sut.RoleCarriesRoleManageGateAsync(90, CancellationToken.None)).ShouldBeFalse();
    }

    [Fact]
    public async Task TheRoleGateSkipsThePermissionQueryWhenTheRolesMenuIsMissing()
    {
        _roleMenus.ListMenuIdsByRoleIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([1]);
        _menus.ListByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Menu(1, "home")]);

        (await Sut.RoleCarriesRoleManageGateAsync(90, CancellationToken.None)).ShouldBeFalse();

        await _rolePermissions.DidNotReceive().ListPermissionsByRoleIdsAsync(
            Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnOwnerWhoseAdminRolesLackTheRolePageDisappearsFromTheWriteScope()
    {
        var caller = new FakeCaller { UserId = 5 };
        Flags(5, isSuperAdmin: false);

        var admin = Fixtures.Role(90, "ota_tc_admin", isAdmin: true);
        Memberships(5, Fixtures.Membership(1, 5, TenantTypes.Company, "C1"));
        Bindings(new Dictionary<int, IReadOnlyList<int>> { [1] = [90] });
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([admin]);

        // No menus granted: the gate closes.
        _roleMenus.ListMenuIdsByRoleIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);

        var (scope, canManage) = await Sut.ResolveRoleManageScopeAsync(caller, CancellationToken.None);

        canManage.ShouldBeFalse();
        scope.Owners.ShouldBeEmpty();

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.AssertCanManageRolesAsync(caller, CancellationToken.None));
        ex.ErrorCode.ShouldBe(ErrorCodes.CallerNotAdmin);
    }

    [Fact]
    public async Task GrantingAWholeDimensionIsPlatformIdentityOnly()
    {
        var caller = new FakeCaller { UserId = 5 };
        Flags(5, isSuperAdmin: false);

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.AssertCanGrantWholeDimensionAsync(caller, TenantTypes.Company, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.SuperAdminRequired);
    }

    [Fact]
    public async Task TheSuperAdministratorCannotBeGivenTenantBindings()
    {
        Flags(9, isSuperAdmin: true);

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.AssertNotSuperAdminTargetAsync(9, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.SuperAdminExclusive);
    }

    [Fact]
    public async Task AnUnknownTargetIsRefusedRatherThanTreatedAsOrdinary()
    {
        _users.FindFlagsAsync(404, Arg.Any<CancellationToken>()).Returns((BackOfficeUserFlags?)null);

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.AssertNotSuperAdminTargetAsync(404, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.MemberNotFound);
    }

    [Fact]
    public async Task TheAdminFlagIsDerivedForWholeDimensionRowsToo()
    {
        var global = Fixtures.Membership(1, 5, tenantCode: IamConstants.ScopeAllSentinelCode, scopeAll: true);
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Role(90, "company_admin", isAdmin: true)]);

        var updated = await Sut.SyncMemberAdminFlagAsync(global, [90], CancellationToken.None);

        updated.IsAdmin.ShouldBeTrue("forcing it false here silently demoted the platform bootstrap row");
        await _members.Received(1).SetAdminAsync(1, true, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnUnchangedAdminFlagIsNotWritten()
    {
        var membership = Fixtures.Membership(1, 5, isAdmin: true);

        await Sut.ApplyMemberAdminFlagAsync(membership, true, CancellationToken.None);

        await _members.DidNotReceive().SetAdminAsync(
            Arg.Any<int>(), Arg.Any<bool>(), Arg.Any<CancellationToken>());
    }

    private void Flags(int userId, bool isSuperAdmin) =>
        _users.FindFlagsAsync(userId, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(userId, BackOfficeUserStatuses.Active, isSuperAdmin, 0));

    private void Memberships(int userId, params TenantMembershipRow[] rows) =>
        _members.ListActiveByUserAsync(userId, Arg.Any<CancellationToken>()).Returns(rows);

    private void Bindings(Dictionary<int, IReadOnlyList<int>> byMember) =>
        _bindings.ListRoleIdsByMemberIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(byMember);
}
