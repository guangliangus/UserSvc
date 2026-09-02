using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Shouldly;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Features.BackOffice.Rbac.Contracts;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Iam;
using Xunit;

using UserSvc.Application.Errors;

namespace UserSvc.UnitTests.Iam;

/// <summary>The two-level cascade, the delegation ceiling and the convergence rule.</summary>
public sealed class RoleGrantsAppServiceTests
{
    private readonly IRoleRepository _roles = Substitute.For<IRoleRepository>();
    private readonly IMenuRepository _menus = Substitute.For<IMenuRepository>();
    private readonly IPermissionRepository _permissions = Substitute.For<IPermissionRepository>();
    private readonly IRoleMenuRepository _roleMenus = Substitute.For<IRoleMenuRepository>();
    private readonly IRolePermissionRepository _rolePermissions = Substitute.For<IRolePermissionRepository>();
    private readonly IUserTenantRoleRepository _bindings = Substitute.For<IUserTenantRoleRepository>();
    private readonly IBackOfficeUserDirectory _users = Substitute.For<IBackOfficeUserDirectory>();
    private readonly ITenantMemberDirectory _members = Substitute.For<ITenantMemberDirectory>();
    private readonly IIamAuditLogRepository _auditLog = Substitute.For<IIamAuditLogRepository>();
    private readonly IAuthzConvergence _convergence = Substitute.For<IAuthzConvergence>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 0, 0, 0, TimeSpan.Zero));

    private AdminScopeService Scopes =>
        new(_users, _members, _bindings, _roles, _roleMenus, _menus, _rolePermissions);

    private RoleGrantsAppService Sut => new(
        _roles,
        _menus,
        _permissions,
        _roleMenus,
        _rolePermissions,
        _bindings,
        Scopes,
        new RoleVisibilityService(Scopes, new ActiveUserRoleReader(_members, _bindings, _roles)),
        new IamAuditWriter(_auditLog, _clock, NullLogger<IamAuditWriter>.Instance),
        _convergence,
        _unitOfWork,
        NullLogger<RoleGrantsAppService>.Instance);

    private static readonly Role PlatformRole = Fixtures.Role(90, "company_admin", isAdmin: true);

    [Fact]
    public async Task GrantingAChildMenuWithoutItsParentIsRefusedNotAutoCompleted()
    {
        var parent = Fixtures.Menu(2, "account");
        var child = Fixtures.Menu(19, IamConstants.MenuCodeUserRoles, parentId: 2);

        _menus.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([child]);
        _menus.ListByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([parent]);

        var ex = await Should.ThrowAsync<RoleGrantViolationException>(() => Sut.ValidateGrantsAsync(
            new FakeCaller { UserId = 1 }, PlatformRole, [child.Code], [], CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.MenuNotGranted);
        ex.Violations.MissingParentMenus.ShouldBe(["account"]);
    }

    [Fact]
    public async Task ASoftDeletedMenuIsRefusedAsUnknown()
    {
        _menus.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Menu(9, "message", status: MenuStatuses.Inactive)]);

        var ex = await Should.ThrowAsync<RoleGrantViolationException>(() => Sut.ValidateGrantsAsync(
            new FakeCaller { UserId = 1 }, PlatformRole, ["message"], [], CancellationToken.None));

        ex.Violations.UnknownMenus.ShouldBe(["message"]);
    }

    [Fact]
    public async Task AServiceLevelPointIsRefusedForATenantRoleAndAllowedForAPlatformRole()
    {
        var tenantRole = Fixtures.Role(
            99, "c1_custom", ownerType: RoleOwnerTypes.Company, ownerCode: "C1");

        _menus.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _permissions.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Permission(249, "uam.audit.read")]);

        var caller = new FakeCaller { UserId = 1 };

        var ex = await Should.ThrowAsync<RoleGrantViolationException>(() => Sut.ValidateGrantsAsync(
            caller, tenantRole, [], ["uam.audit.read"], CancellationToken.None));
        ex.Violations.NullMenuPermissions.ShouldBe(["uam.audit.read"]);

        var (_, _, permissionCodes) = await Sut.ValidateGrantsAsync(
            caller, PlatformRole, [], ["uam.audit.read"], CancellationToken.None);
        permissionCodes.ShouldBe(["uam.audit.read"]);
    }

    [Fact]
    public async Task APointOutsideTheGrantedMenusIsRefused()
    {
        _menus.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _permissions.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Permission(1, "order.read", menuId: 4)]);

        var ex = await Should.ThrowAsync<RoleGrantViolationException>(() => Sut.ValidateGrantsAsync(
            new FakeCaller { UserId = 1 }, PlatformRole, [], ["order.read"], CancellationToken.None));

        ex.Violations.PermissionsOutsideMenus.ShouldBe(["order.read"]);
    }

    [Fact]
    public async Task ATenantCallerCannotDelegateWhatTheyDoNotHold()
    {
        var tenantRole = Fixtures.Role(
            99, "c1_custom", ownerType: RoleOwnerTypes.Company, ownerCode: "C1");

        var menu = Fixtures.Menu(4, "order");
        _menus.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([menu]);
        _permissions.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([]);

        // The caller holds nothing, so even a legal menu is not theirs to pass on.
        var caller = FakeCaller.Tenant(5, TenantTypes.Company, "C1").Holding(menus: []);

        var ex = await Should.ThrowAsync<RoleGrantViolationException>(() => Sut.ValidateGrantsAsync(
            caller, tenantRole, ["order"], [], CancellationToken.None));

        ex.Violations.MenusNotDelegable.ShouldBe(["order"]);
    }

    [Fact]
    public async Task APlatformCallerIsNotBoundBySubsetOfCreator()
    {
        var menu = Fixtures.Menu(4, "order");
        _menus.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([menu]);
        _permissions.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([]);

        var (menuIds, menuCodes, _) = await Sut.ValidateGrantsAsync(
            new FakeCaller { UserId = 1 }, PlatformRole, ["order"], [], CancellationToken.None);

        menuIds.ShouldBe([4]);
        menuCodes.ShouldBe(["order"]);
    }

    [Fact]
    public async Task AChildCannotBeGrantedMoreThanItsLeader()
    {
        var child = Fixtures.Role(91, "product_op", parentRoleId: 90);
        var menu = Fixtures.Menu(4, "order");

        _menus.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([menu]);
        _permissions.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _roles.FindByIdAsync(90, Arg.Any<CancellationToken>()).Returns(PlatformRole);

        // The leader holds nothing.
        _roleMenus.ListMenuIdsByRoleIdsAsync(
                Arg.Is<IReadOnlyCollection<int>>(ids => ids.Contains(90)), Arg.Any<CancellationToken>())
            .Returns([]);
        _rolePermissions.ListPermissionsByRoleIdsAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);

        var ex = await Should.ThrowAsync<RoleGrantViolationException>(() => Sut.ValidateGrantsAsync(
            new FakeCaller { UserId = 1 }, child, ["order"], [], CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleGrantsExceedParent);
        ex.Violations.BeyondParentMenus.ShouldBe(["order"]);
    }

    [Fact]
    public async Task ShrinkingChildrenBehindTheOperatorIsRefused()
    {
        var child = Fixtures.Role(91, "product_op", parentRoleId: 90);
        _roles.ListChildrenAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([child]);
        _roleMenus.ListMenuIdsByRoleIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([4]);
        _menus.ListByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Menu(4, "order")]);
        _rolePermissions.ListPermissionsByRoleIdsAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);

        var ex = await Should.ThrowAsync<RoleSetException>(
            () => Sut.AssertChildrenWithinGrantsAsync(90, [], [], CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleGrantsExceedParent);
        ex.Roles.ShouldBe(["product_op"]);
    }

    [Fact]
    public async Task ASoftDeletedGrantDoesNotCountAsHeld()
    {
        _roleMenus.ListMenuIdsByRoleIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([9]);
        _menus.ListByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Menu(9, "message", status: MenuStatuses.Inactive)]);
        _rolePermissions.ListPermissionsByRoleIdsAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Permission(1, "old.point", menuId: 9, status: PermissionStatuses.Inactive)]);

        var (menuCodes, permissionCodes) = await Sut.LoadRoleGrantCodesAsync(90, CancellationToken.None);

        menuCodes.ShouldBeEmpty("counting it would make the child and re-parent checks unsatisfiable");
        permissionCodes.ShouldBeEmpty();
    }

    [Fact]
    public async Task TheMenuClosureWalksUpTheParentChain()
    {
        _permissions.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Permission(1, "order.tour.read", menuId: 24)]);

        _menus.ListActiveAsync(Arg.Any<CancellationToken>()).Returns(
        [
            Fixtures.Menu(4, "order"),
            Fixtures.Menu(24, "order-tour", parentId: 4),
        ]);

        var codes = await Sut.DeriveMenuClosureForPermissionsAsync(["order.tour.read"], CancellationToken.None);

        codes.ShouldBe(["order", "order-tour"]);
    }

    [Fact]
    public async Task ARevocationReissuesTokensWhileAnAdditionOnlyDropsTheCachedFace()
    {
        SetUpSaveablePath(existingMenuCodes: ["order", "product"]);

        await Sut.SaveRoleGrantsAsync(
            new FakeCaller { UserId = 1 },
            90,
            new SaveRoleGrantsRequest { MenuCodes = ["order"] },
            CancellationToken.None);

        await _convergence.Received(1).BumpTokenVersionAsync(
            Arg.Is<IReadOnlyCollection<int>>(ids => ids.Contains(42)), Arg.Any<CancellationToken>());
        await _convergence.DidNotReceive().InvalidateAuthzAsync(
            Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task APurelyAdditiveSaveDoesNotReissueTokens()
    {
        SetUpSaveablePath(existingMenuCodes: []);

        await Sut.SaveRoleGrantsAsync(
            new FakeCaller { UserId = 1 },
            90,
            new SaveRoleGrantsRequest { MenuCodes = ["order"] },
            CancellationToken.None);

        await _convergence.DidNotReceive().BumpTokenVersionAsync(
            Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>());
        await _convergence.Received(1).InvalidateAuthzAsync(
            Arg.Is<IReadOnlyCollection<int>>(ids => ids.Contains(42)), Arg.Any<CancellationToken>());
    }

    /// <summary>Wires the whole save path for a platform caller editing a platform role.</summary>
    private void SetUpSaveablePath(IReadOnlyList<string> existingMenuCodes)
    {
        _users.FindFlagsAsync(1, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(1, BackOfficeUserStatuses.Active, true, 0));

        var order = Fixtures.Menu(4, "order");
        var product = Fixtures.Menu(3, "product");

        _roles.FindByIdAsync(90, Arg.Any<CancellationToken>())
            .Returns(Fixtures.Role(90, "company_admin", isAdmin: false));

        _menus.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([order]);
        _permissions.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([]);

        var existingIds = existingMenuCodes.Contains("product") ? new[] { 4, 3 } : [4];
        _roleMenus.ListMenuIdsByRoleIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(existingMenuCodes.Count == 0 ? [] : existingIds);

        _menus.ListByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(existingMenuCodes.Contains("product") ? [order, product] : [order]);

        _rolePermissions.ListPermissionsByRoleIdsAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);

        _bindings.ListUserIdsByRoleIdAsync(90, Arg.Any<CancellationToken>()).Returns([42]);

        _unitOfWork.ExecuteInTransactionAsync(
                Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns(call => call.Arg<Func<CancellationToken, Task>>()(CancellationToken.None));
    }
}
