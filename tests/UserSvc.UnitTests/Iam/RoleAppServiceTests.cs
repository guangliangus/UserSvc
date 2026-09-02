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

/// <summary>The role write path: who may create what, and under which leader.</summary>
public sealed class RoleAppServiceTests
{
    private readonly IRoleRepository _roles = Substitute.For<IRoleRepository>();
    private readonly IRoleMenuRepository _roleMenus = Substitute.For<IRoleMenuRepository>();
    private readonly IRolePermissionRepository _rolePermissions = Substitute.For<IRolePermissionRepository>();
    private readonly IUserTenantRoleRepository _bindings = Substitute.For<IUserTenantRoleRepository>();
    private readonly IBackOfficeUserDirectory _users = Substitute.For<IBackOfficeUserDirectory>();
    private readonly ITenantMemberDirectory _members = Substitute.For<ITenantMemberDirectory>();
    private readonly IMenuRepository _menus = Substitute.For<IMenuRepository>();
    private readonly IPermissionRepository _permissions = Substitute.For<IPermissionRepository>();
    private readonly IIamAuditLogRepository _auditLog = Substitute.For<IIamAuditLogRepository>();
    private readonly IAuthzConvergence _convergence = Substitute.For<IAuthzConvergence>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 0, 0, 0, TimeSpan.Zero));

    private AdminScopeService Scopes =>
        new(_users, _members, _bindings, _roles, _roleMenus, _menus, _rolePermissions);

    private RoleVisibilityService Visibility =>
        new(Scopes, new ActiveUserRoleReader(_members, _bindings, _roles));

    private RoleAppService Sut => new(
        _roles,
        _roleMenus,
        _rolePermissions,
        _bindings,
        Scopes,
        Visibility,
        new RoleDelegationService(Scopes, _members, _bindings, _roles),
        new RoleGrantsAppService(
            _roles, _menus, _permissions, _roleMenus, _rolePermissions, _bindings, Scopes, Visibility,
            new IamAuditWriter(_auditLog, _clock, NullLogger<IamAuditWriter>.Instance),
            _convergence, _unitOfWork, NullLogger<RoleGrantsAppService>.Instance),
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

    private static CreateRoleRequest Request(
        string code = "new_role",
        string category = RoleCategories.Company,
        string? ownerType = null,
        string? ownerCode = null,
        bool isAdmin = false,
        int? parentRoleId = null) => new()
        {
            Code = code,
            Name = code,
            Category = category,
            OwnerType = ownerType,
            OwnerCode = ownerCode,
            IsAdmin = isAdmin,
            ParentRoleId = parentRoleId,
        };

    [Fact]
    public async Task ATakenCodeIsRefusedBeforeTheWrite()
    {
        _roles.ExistsByCodeAsync("new_role", Arg.Any<CancellationToken>()).Returns(true);

        var ex = await Should.ThrowAsync<ConflictException>(
            () => Sut.CreateRoleAsync(PlatformOwner, Request(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleCodeExists);
    }

    [Fact]
    public async Task TheReservedAdminCodeIsRefusedForATenantOwner()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.CreateRoleAsync(
            PlatformOwner,
            Request(code: IamConstants.RoleCodeAdmin, ownerType: RoleOwnerTypes.Company, ownerCode: "C1"),
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleCodeReserved);
    }

    [Fact]
    public async Task TheWholeDimensionSentinelIsNotAValidOwner()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.CreateRoleAsync(
            PlatformOwner,
            Request(ownerType: RoleOwnerTypes.Company, ownerCode: IamConstants.ScopeAllSentinelCode),
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleOwnerRequired);
    }

    [Fact]
    public async Task ATenantOwnedRoleIsPinnedToItsOwnDimension()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.CreateRoleAsync(
            PlatformOwner,
            Request(category: RoleCategories.Supplier, ownerType: RoleOwnerTypes.Company, ownerCode: "C1"),
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleCategoryInvalid);
    }

    [Fact]
    public async Task TheEmptyCategoryIsNotAcceptedAsInput()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.CreateRoleAsync(PlatformOwner, Request(category: string.Empty), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleCategoryInvalid);
    }

    [Fact]
    public async Task APlatformRoleMayBeCategorisedForSuppliers()
    {
        var created = await Sut.CreateRoleAsync(
            PlatformOwner, Request(category: RoleCategories.Supplier), CancellationToken.None);

        created.Category.ShouldBe(RoleCategories.Supplier);
        created.OwnerType.ShouldBe(RoleOwnerTypes.System);
        created.OwnerCode.ShouldBeNull();
    }

    [Fact]
    public async Task AnAdministratorRoleMustBeOwnedByThePlatform()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.CreateRoleAsync(
            PlatformOwner,
            Request(isAdmin: true, ownerType: RoleOwnerTypes.Company, ownerCode: "C1"),
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
        ex.Message.ShouldContain("SYSTEM");
    }

    [Fact]
    public async Task TheParentMustBeAnAdministratorRole()
    {
        _roles.FindByIdAsync(91, Arg.Any<CancellationToken>())
            .Returns(Fixtures.Role(91, "product_op"));

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.CreateRoleAsync(PlatformOwner, Request(parentRoleId: 91), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleParentInvalid);
    }

    [Fact]
    public async Task AParentThatWouldFormACycleIsRefused()
    {
        var leader = Fixtures.Role(89, "supplier_admin", isAdmin: true, parentRoleId: 98);
        var middle = Fixtures.Role(98, "product_supplier_admin", isAdmin: true, parentRoleId: 50);
        var target = Fixtures.Role(50, "target", isAdmin: true);

        _roles.FindByIdAsync(50, Arg.Any<CancellationToken>()).Returns(target);
        _roles.FindByIdAsync(89, Arg.Any<CancellationToken>()).Returns(leader);
        _roles.FindByIdAsync(98, Arg.Any<CancellationToken>()).Returns(middle);

        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.UpdateRoleAsync(
            PlatformOwner,
            50,
            new UpdateRoleRequest { Name = "target", ParentRoleId = 89 },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleParentInvalid);
        ex.Message.ShouldContain("cycle");
    }

    [Fact]
    public async Task ARoleThatStillLeadsAGroupCannotBeDeleted()
    {
        _roles.FindByIdAsync(89, Arg.Any<CancellationToken>())
            .Returns(Fixtures.Role(89, "supplier_admin", isAdmin: true));
        _roles.CountChildrenAsync(89, Arg.Any<CancellationToken>()).Returns(2);

        var ex = await Should.ThrowAsync<ConflictException>(
            () => Sut.DeleteRoleAsync(PlatformOwner, 89, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleHasChildren);
    }

    [Fact]
    public async Task ARoleStillBoundToAnActiveMemberCannotBeDeleted()
    {
        _roles.FindByIdAsync(91, Arg.Any<CancellationToken>()).Returns(Fixtures.Role(91, "product_op"));
        _roles.CountChildrenAsync(91, Arg.Any<CancellationToken>()).Returns(0);
        _bindings.CountActiveByRoleIdAsync(91, Arg.Any<CancellationToken>()).Returns(1);

        var ex = await Should.ThrowAsync<ConflictException>(
            () => Sut.DeleteRoleAsync(PlatformOwner, 91, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleInUse);
    }

    [Fact]
    public async Task AnEmptyNameIsNotADuplicate()
    {
        var answer = await Sut.RoleNameExistsAsync(PlatformOwner, "   ", 0, CancellationToken.None);

        answer.Exists.ShouldBeFalse();
        await _roles.DidNotReceive().ExistsByNameAsync(
            Arg.Any<string>(), Arg.Any<int>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TheNameProbeIsBehindTheWriteGate()
    {
        _users.FindFlagsAsync(5, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(5, BackOfficeUserStatuses.Active, false, 0));
        _members.ListActiveByUserAsync(5, Arg.Any<CancellationToken>()).Returns([]);

        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.RoleNameExistsAsync(
            new FakeCaller { UserId = 5 }, "anything", 0, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.CallerNotAdmin);
    }

    [Fact]
    public async Task MyRoleScopeAnswersFalseRatherThanRefusing()
    {
        _users.FindFlagsAsync(5, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(5, BackOfficeUserStatuses.Active, false, 0));
        _members.ListActiveByUserAsync(5, Arg.Any<CancellationToken>()).Returns([]);

        var scope = await Sut.GetMyRoleScopeAsync(new FakeCaller { UserId = 5 }, CancellationToken.None);

        scope.CanManageRoles.ShouldBeFalse();
        scope.IsSuperAdmin.ShouldBeFalse();
        scope.Owners.ShouldBeEmpty();
        scope.AdminRoles.ShouldBeEmpty();
    }

    [Fact]
    public async Task AnUncategorisedRoleIsBindableNowhere()
    {
        _roles.ListAllAsync(Arg.Any<CancellationToken>())
            .Returns([Fixtures.Role(1, "legacy", category: RoleCategories.Unset)]);

        var list = await Sut.GetRolesAsync(PlatformOwner, CancellationToken.None);

        var legacy = list.ShouldHaveSingleItem();
        legacy.Bindable.ShouldBeFalse();
        legacy.BindableCompany.ShouldBeFalse();
        legacy.BindableSupplier.ShouldBeFalse();
        legacy.Readonly.ShouldBeFalse("the platform owner may still edit it");
    }

    [Fact]
    public async Task AParentCodeIsResolvedFromTheFullCatalogueEvenWhenTheParentIsHidden()
    {
        var leader = Fixtures.Role(89, "supplier_admin", isAdmin: true);
        var child = Fixtures.Role(91, "product_op", parentRoleId: 89);
        _roles.ListAllAsync(Arg.Any<CancellationToken>()).Returns([leader, child]);

        var list = await Sut.GetRolesAsync(PlatformOwner, CancellationToken.None);

        list.Single(role => role.Id == 91).ParentRoleCode.ShouldBe("supplier_admin");
    }
}
