using NSubstitute;
using Shouldly;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;
using Xunit;

using UserSvc.Application.Errors;

namespace UserSvc.UnitTests.Iam;

/// <summary>The delegation ceiling: what a caller may hand to somebody else.</summary>
public sealed class RoleDelegationServiceTests
{
    private readonly IBackOfficeUserDirectory _users = Substitute.For<IBackOfficeUserDirectory>();
    private readonly ITenantMemberDirectory _members = Substitute.For<ITenantMemberDirectory>();
    private readonly IUserTenantRoleRepository _bindings = Substitute.For<IUserTenantRoleRepository>();
    private readonly IRoleRepository _roles = Substitute.For<IRoleRepository>();
    private readonly IRoleMenuRepository _roleMenus = Substitute.For<IRoleMenuRepository>();
    private readonly IMenuRepository _menus = Substitute.For<IMenuRepository>();
    private readonly IRolePermissionRepository _rolePermissions = Substitute.For<IRolePermissionRepository>();

    private RoleDelegationService Sut => new(
        new AdminScopeService(_users, _members, _bindings, _roles, _roleMenus, _menus, _rolePermissions),
        _members,
        _bindings,
        _roles);

    private static readonly Role SupplierAdmin = Fixtures.Role(89, "supplier_admin", isAdmin: true);
    private static readonly Role ProductSupplierAdmin =
        Fixtures.Role(98, "product_supplier_admin", isAdmin: true, parentRoleId: 89);
    private static readonly Role ProductOp = Fixtures.Role(91, "product_op", parentRoleId: 98);
    private static readonly Role OtherTenantRole = Fixtures.Role(
        99, "c2_custom", ownerType: RoleOwnerTypes.Company, ownerCode: "C2", parentRoleId: 98);

    [Fact]
    public async Task ALeaderDelegatesItsWholeSubtreeButNotItself()
    {
        Flags(5, false);
        _members.FindAsync(5, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns(Fixtures.Membership(1, 5, TenantTypes.Company, "C1", isAdmin: true));
        _bindings.ListByMemberIdAsync(1, Arg.Any<CancellationToken>())
            .Returns([new UserTenantRoleBinding(1, 1, 89)]);
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([SupplierAdmin]);
        _roles.ListDescendantsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([ProductSupplierAdmin, ProductOp, OtherTenantRole]);

        var ids = await Sut.DelegableRoleIdsAsync(5, TenantTypes.Company, "C1", CancellationToken.None);

        ids.ShouldContain(98, "a leader appoints its own sub-leaders");
        ids.ShouldContain(91);
        ids.ShouldNotContain(89, "'below me' does not include me - cloning yourself onto a peer is refused");
        ids.ShouldNotContain(99, "another tenant's role under a shared leader stays out");
    }

    [Fact]
    public async Task HoldingANonAdministratorRoleDelegatesNothing()
    {
        Flags(5, false);
        _members.FindAsync(5, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns(Fixtures.Membership(1, 5, TenantTypes.Company, "C1"));
        _bindings.ListByMemberIdAsync(1, Arg.Any<CancellationToken>())
            .Returns([new UserTenantRoleBinding(1, 1, 91)]);
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([ProductOp]);

        var ids = await Sut.DelegableRoleIdsAsync(5, TenantTypes.Company, "C1", CancellationToken.None);

        ids.ShouldBeEmpty("holding a role is not authority to hand it out");
    }

    [Fact]
    public async Task ADisabledMembershipDelegatesNothing()
    {
        Flags(5, false);
        _members.FindAsync(5, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns(Fixtures.Membership(
                1, 5, TenantTypes.Company, "C1", isAdmin: true,
                status: TenantMembershipStatuses.Disabled));

        (await Sut.DelegableRoleIdsAsync(5, TenantTypes.Company, "C1", CancellationToken.None))
            .ShouldBeEmpty();
    }

    [Fact]
    public async Task ThePlatformOwnerBindsEverythingExceptOtherTenantsRoles()
    {
        Flags(1, true);
        _roles.ListAllAsync(Arg.Any<CancellationToken>())
            .Returns([SupplierAdmin, ProductOp, OtherTenantRole]);

        var ids = await Sut.DelegableRoleIdsAsync(1, TenantTypes.Company, "C1", CancellationToken.None);

        ids.ShouldBe([89, 91]);
    }

    [Fact]
    public async Task ACategoryMismatchIsItsOwnRefusalNotACeilingRefusal()
    {
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Fixtures.Role(50, "component_op", category: RoleCategories.Supplier)]);

        var ex = await Should.ThrowAsync<RoleSetException>(
            () => Sut.AssertRolesFitTenantTypeAsync(TenantTypes.Company, [50], CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleCategoryMismatch);
        ex.Roles.ShouldBe(["component_op"]);
    }

    [Fact]
    public void ATenantsOwnRoleCannotRideAWholeDimensionGrant()
    {
        var ex = Should.Throw<RoleSetException>(() => RoleDelegationService.AssertNoTenantOwnedRoles(
            [OtherTenantRole, SupplierAdmin]));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleNotGloballyAssignable);
        ex.Roles.ShouldBe(["c2_custom"]);
    }

    [Fact]
    public async Task ValidateDelegationNamesTheCodesThatAreOutOfRange()
    {
        Flags(5, false);
        _members.FindAsync(5, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns((TenantMembershipRow?)null);
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([ProductOp]);

        var violations = await Sut.ValidateDelegationAsync(
            5, TenantTypes.Company, "C1", [91], CancellationToken.None);

        violations.ShouldBe(["product_op"]);
    }

    private void Flags(int userId, bool isSuperAdmin) =>
        _users.FindFlagsAsync(userId, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(userId, BackOfficeUserStatuses.Active, isSuperAdmin, 0));
}
