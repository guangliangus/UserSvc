using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Features.BackOffice.Rbac.Contracts;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Iam;
using Xunit;

namespace UserSvc.UnitTests.Iam;

/// <summary>The menu registry: tree shaping, the switched-off audience gate, and the delete order.</summary>
public sealed class MenuAppServiceTests
{
    private readonly IMenuRepository _menus = Substitute.For<IMenuRepository>();
    private readonly IPermissionRepository _permissions = Substitute.For<IPermissionRepository>();
    private readonly IBackOfficeUserDirectory _users = Substitute.For<IBackOfficeUserDirectory>();
    private readonly ITenantMemberDirectory _members = Substitute.For<ITenantMemberDirectory>();
    private readonly IUserTenantRoleRepository _bindings = Substitute.For<IUserTenantRoleRepository>();
    private readonly IRoleRepository _roles = Substitute.For<IRoleRepository>();
    private readonly IRoleMenuRepository _roleMenus = Substitute.For<IRoleMenuRepository>();
    private readonly IRolePermissionRepository _rolePermissions = Substitute.For<IRolePermissionRepository>();
    private readonly IIamAuditLogRepository _auditLog = Substitute.For<IIamAuditLogRepository>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 0, 0, 0, TimeSpan.Zero));

    private MenuAppService Sut => new(
        _menus,
        _permissions,
        new AdminScopeService(_users, _members, _bindings, _roles, _roleMenus, _menus, _rolePermissions),
        new IamAuditWriter(_auditLog, _clock, NullLogger<IamAuditWriter>.Instance),
        _unitOfWork,
        _clock);

    private FakeCaller PlatformOwner
    {
        get
        {
            _users.FindFlagsAsync(1, Arg.Any<CancellationToken>())
                .Returns(new BackOfficeUserFlags(1, BackOfficeUserStatuses.Active, true, 0));
            return new FakeCaller { UserId = 1 };
        }
    }

    /// <summary>An ordinary caller who holds the point the management tree asks for, and is not the
    /// platform owner - so a test that passes does so through the gate, not around it.</summary>
    private static FakeCaller RoleAdmin =>
        new FakeCaller { UserId = 7 }.Holding(permissions: [IamConstants.PermissionCodeRoleManage]);

    [Fact]
    public async Task TheManagementTreeIsRefusedToACallerHoldingNeitherPoint()
    {
        _users.FindFlagsAsync(9, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(9, BackOfficeUserStatuses.Active, false, 0));
        var stranger = new FakeCaller { UserId = 9 };

        var thrown = await Should.ThrowAsync<ForbiddenException>(
            () => Sut.GetMenuTreeAsync(stranger, null, null, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.Forbidden);
        await _menus.DidNotReceive().ListAllAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TheManagementTreeOpensOnMemberReadAsWellAsRoleManage()
    {
        _menus.ListAllAsync(Arg.Any<CancellationToken>()).Returns([Fixtures.Menu(4, "order")]);
        _permissions.ListByMenuIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        var memberReader = new FakeCaller { UserId = 8 }
            .Holding(permissions: [IamConstants.PermissionCodeMemberRead]);

        var tree = await Sut.GetMenuTreeAsync(memberReader, null, null, CancellationToken.None);

        tree.Items.ShouldHaveSingleItem("a grants payload is unreadable without the menu names");
    }

    [Fact]
    public async Task ANodeWhoseParentWasFilteredOutIsPromotedToARoot()
    {
        _menus.ListAllAsync(Arg.Any<CancellationToken>()).Returns(
        [
            Fixtures.Menu(2, "account", status: MenuStatuses.Inactive),
            Fixtures.Menu(19, IamConstants.MenuCodeUserRoles, parentId: 2),
        ]);
        _permissions.ListByMenuIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);

        var tree = await Sut.GetMenuTreeAsync(RoleAdmin, null, MenuStatuses.Active, CancellationToken.None);

        tree.Items.ShouldHaveSingleItem();
        tree.Items[0].Code.ShouldBe(IamConstants.MenuCodeUserRoles);
        tree.Items[0].ParentId.ShouldBe(2, "the node still reports where it came from");
    }

    [Fact]
    public async Task AStatusFilterAppliesToThePermissionPointsToo()
    {
        _menus.ListAllAsync(Arg.Any<CancellationToken>()).Returns([Fixtures.Menu(4, "order")]);
        _permissions.ListByMenuIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(
            [
                Fixtures.Permission(1, "order.read", menuId: 4),
                Fixtures.Permission(2, "order.retired", menuId: 4, status: PermissionStatuses.Inactive),
            ]);

        var tree = await Sut.GetMenuTreeAsync(RoleAdmin, null, MenuStatuses.Active, CancellationToken.None);

        tree.Items[0].Permissions.Select(point => point.Code).ShouldBe(["order.read"]);
    }

    [Fact]
    public async Task TheAudienceParameterIsInert()
    {
        _menus.ListAllAsync(Arg.Any<CancellationToken>()).Returns(
        [
            Fixtures.Menu(6, "supplier"),
        ]);
        _permissions.ListByMenuIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);

        var tree = await Sut.GetMenuTreeAsync(RoleAdmin, MenuAudiences.Company, null, CancellationToken.None);

        tree.Items.ShouldHaveSingleItem(
            "audience filtering is switched off on purpose; do not 'fix' this into a filter");
    }

    [Fact]
    public async Task AGrantedNodeReattachesToItsNearestGrantedAncestor()
    {
        _menus.ListActiveAsync(Arg.Any<CancellationToken>()).Returns(
        [
            Fixtures.Menu(5, "basic"),
            Fixtures.Menu(25, "basic-poi_aoi", parentId: 5),
            Fixtures.Menu(30, "basic-aoi", parentId: 25),
        ]);

        // The middle node is not granted.
        var tree = await Sut.GetGrantedMenuTreeAsync(["basic", "basic-aoi"], CancellationToken.None);

        tree.Items.ShouldHaveSingleItem();
        tree.Items[0].Code.ShouldBe("basic");
        tree.Items[0].Children.Single().Code.ShouldBe(
            "basic-aoi", "flattening it to a root would lose the hierarchy");
        tree.Items[0].Permissions.ShouldBeEmpty("the sidebar tree carries no permission points");
    }

    [Fact]
    public async Task ADuplicateCodeIsRefused()
    {
        _menus.FindByCodeAsync("order", Arg.Any<CancellationToken>()).Returns(Fixtures.Menu(4, "order"));

        var ex = await Should.ThrowAsync<ConflictException>(() => Sut.CreateMenuAsync(
            PlatformOwner,
            new CreateMenuRequest
            {
                Code = "order",
                Name = new Dictionary<string, string> { ["en"] = "Orders" },
            },
            CancellationToken.None));

        // Not a dedicated code. This is the current contract, odd as it looks.
        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
    }

    [Fact]
    public async Task ANameWithNoLocaleIsRefused()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.CreateMenuAsync(
            PlatformOwner,
            new CreateMenuRequest { Code = "x", Name = new Dictionary<string, string>() },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
    }

    [Fact]
    public async Task AnEmptyAudienceMeansAllThreeTenantTypes()
    {
        _menus.FindByCodeAsync("x", Arg.Any<CancellationToken>()).Returns((Menu?)null);

        var created = await Sut.CreateMenuAsync(
            PlatformOwner,
            new CreateMenuRequest { Code = "x", Name = new Dictionary<string, string> { ["en"] = "X" } },
            CancellationToken.None);

        created.Audience.ShouldBe(["company", "platform", "supplier"]);
        created.Status.ShouldBe(MenuStatuses.Active);
    }

    [Fact]
    public async Task AnUnknownAudienceValueIsRefusedByName()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.CreateMenuAsync(
            PlatformOwner,
            new CreateMenuRequest
            {
                Code = "x",
                Name = new Dictionary<string, string> { ["en"] = "X" },
                Audience = ["everyone"],
            },
            CancellationToken.None));

        ex.Message.ShouldContain("everyone");
    }

    [Fact]
    public async Task AMenuWithChildrenCannotBeDeleted()
    {
        _menus.FindByIdAsync(5, Arg.Any<CancellationToken>()).Returns(Fixtures.Menu(5, "basic"));
        _menus.ListChildrenAsync(5, Arg.Any<CancellationToken>())
            .Returns([Fixtures.Menu(25, "basic-poi_aoi", parentId: 5)]);

        var ex = await Should.ThrowAsync<ConflictException>(
            () => Sut.DeleteMenuAsync(PlatformOwner, 5, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.MenuHasChildren);
    }

    [Fact]
    public async Task DeletingAMenuRemovesItsPermissionPointsFirst()
    {
        _menus.FindByIdAsync(4, Arg.Any<CancellationToken>()).Returns(Fixtures.Menu(4, "order"));
        _menus.ListChildrenAsync(4, Arg.Any<CancellationToken>()).Returns([]);
        _permissions.ListByMenuIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Permission(1, "order.read", menuId: 4)]);
        _unitOfWork.ExecuteInTransactionAsync(
                Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns(call => call.Arg<Func<CancellationToken, Task>>()(CancellationToken.None));

        await Sut.DeleteMenuAsync(PlatformOwner, 4, CancellationToken.None);

        Received.InOrder(() =>
        {
            _permissions.DeleteByMenuIdAsync(4, Arg.Any<CancellationToken>());
            _menus.Remove(Arg.Any<Menu>());
        });

        await _auditLog.Received(1).AppendAsync(
            Arg.Is<IamAuditLog>(entry => entry.Action == IamAuditActions.MenuDelete),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ATenantCallerCannotTouchTheRegistry()
    {
        _users.FindFlagsAsync(5, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(5, BackOfficeUserStatuses.Active, false, 0));

        var caller = FakeCaller.Tenant(5, TenantTypes.Company, "C1");

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.DeleteMenuAsync(caller, 4, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.SuperAdminRequired);
    }

    [Fact]
    public async Task AFailingAuditWriteDoesNotFailACommittedDelete()
    {
        _menus.FindByIdAsync(4, Arg.Any<CancellationToken>()).Returns(Fixtures.Menu(4, "order"));
        _menus.ListChildrenAsync(4, Arg.Any<CancellationToken>()).Returns([]);
        _permissions.ListByMenuIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _unitOfWork.ExecuteInTransactionAsync(
                Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns(call => call.Arg<Func<CancellationToken, Task>>()(CancellationToken.None));
        _auditLog.AppendAsync(Arg.Any<IamAuditLog>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException(new InvalidOperationException("audit is down")));

        await Sut.DeleteMenuAsync(PlatformOwner, 4, CancellationToken.None);
    }
}
