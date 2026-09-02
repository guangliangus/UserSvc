using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Iam;
using Xunit;

namespace UserSvc.UnitTests.Iam;

/// <summary>
/// The permission-point catalogue, and the gate in front of it.
/// <para>
/// The catalogue read carried no check at all in the first cut - the route's permission point was
/// named in a doc comment and enforced nowhere - which handed every authenticated back-office
/// account the full list of points the platform can enforce. These tests pin the gate so it cannot
/// quietly go away again.
/// </para>
/// </summary>
public sealed class PermissionCatalogAppServiceTests
{
    private readonly IPermissionRepository _permissions = Substitute.For<IPermissionRepository>();
    private readonly IRoleRepository _roles = Substitute.For<IRoleRepository>();
    private readonly IBackOfficeUserDirectory _users = Substitute.For<IBackOfficeUserDirectory>();
    private readonly ITenantMemberDirectory _members = Substitute.For<ITenantMemberDirectory>();
    private readonly IUserTenantRoleRepository _bindings = Substitute.For<IUserTenantRoleRepository>();
    private readonly IRoleMenuRepository _roleMenus = Substitute.For<IRoleMenuRepository>();
    private readonly IMenuRepository _menus = Substitute.For<IMenuRepository>();
    private readonly IRolePermissionRepository _rolePermissions = Substitute.For<IRolePermissionRepository>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 0, 0, 0, TimeSpan.Zero));

    private AdminScopeService Scopes =>
        new(_users, _members, _bindings, _roles, _roleMenus, _menus, _rolePermissions);

    private PermissionCatalogAppService Sut => new(
        _permissions,
        _roles,
        Scopes,
        new RoleVisibilityService(Scopes, new ActiveUserRoleReader(_members, _bindings, _roles)),
        new UserVisibilityService(Scopes, _members, _bindings, _roles),
        _unitOfWork,
        _clock);

    [Fact]
    public async Task TheCatalogueIsRefusedToACallerWithoutTheRoleManagePoint()
    {
        _users.FindFlagsAsync(9, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(9, BackOfficeUserStatuses.Active, false, 0));
        var stranger = new FakeCaller { UserId = 9 };

        var thrown = await Should.ThrowAsync<ForbiddenException>(
            () => Sut.GetPermissionsAsync(stranger, CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.Forbidden);
        await _permissions.DidNotReceive().ListAllAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnUnresolvedAuthorizationFaceDeniesRatherThanOpens()
    {
        // The empty face is what the API layer supplies when the resolution is missing. It has to
        // read as "holds nothing", never as "no requirement stated".
        _users.FindFlagsAsync(9, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(9, BackOfficeUserStatuses.Active, false, 0));
        var faceless = new FakeCaller { UserId = 9, Authz = EffectiveAuthz.Empty };

        await Should.ThrowAsync<ForbiddenException>(
            () => Sut.GetPermissionsAsync(faceless, CancellationToken.None));
    }

    [Fact]
    public async Task ARoleAdministratorReadsTheWholeCatalogueIncludingInactivePoints()
    {
        _permissions.ListAllAsync(Arg.Any<CancellationToken>()).Returns(
        [
            Fixtures.Permission(1, "order.read", menuId: 4),
            Fixtures.Permission(2, "order.retired", menuId: 4, status: PermissionStatuses.Inactive),
        ]);
        var admin = new FakeCaller { UserId = 7 }
            .Holding(permissions: [IamConstants.PermissionCodeRoleManage]);

        var catalogue = await Sut.GetPermissionsAsync(admin, CancellationToken.None);

        catalogue.Select(point => point.Code).ShouldBe(["order.read", "order.retired"],
            "this is the catalogue, not anybody's grant: an INACTIVE point must stay visible to be reactivated");
    }

    [Fact]
    public async Task ThePlatformOwnerReadsTheCatalogueWithoutHoldingAnyGrantRow()
    {
        // Their access is the account-row flag, not grant rows, so an unresolved face must not lock
        // the strongest account in the system out of the page it needs most.
        _users.FindFlagsAsync(1, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(1, BackOfficeUserStatuses.Active, true, 0));
        _permissions.ListAllAsync(Arg.Any<CancellationToken>())
            .Returns([Fixtures.Permission(1, "order.read", menuId: 4)]);

        var catalogue = await Sut.GetPermissionsAsync(
            new FakeCaller { UserId = 1 }, CancellationToken.None);

        catalogue.ShouldHaveSingleItem();
    }
}
