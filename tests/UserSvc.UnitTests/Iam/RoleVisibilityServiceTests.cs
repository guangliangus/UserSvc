using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;
using Xunit;

namespace UserSvc.UnitTests.Iam;

/// <summary>
/// The role list has no route permission at all, so these tests are its access control.
/// </summary>
public sealed class RoleVisibilityServiceTests
{
    private readonly IBackOfficeUserDirectory _users = Substitute.For<IBackOfficeUserDirectory>();
    private readonly ITenantMemberDirectory _members = Substitute.For<ITenantMemberDirectory>();
    private readonly IUserTenantRoleRepository _bindings = Substitute.For<IUserTenantRoleRepository>();
    private readonly IRoleRepository _roles = Substitute.For<IRoleRepository>();
    private readonly IRoleMenuRepository _roleMenus = Substitute.For<IRoleMenuRepository>();
    private readonly IMenuRepository _menus = Substitute.For<IMenuRepository>();
    private readonly IRolePermissionRepository _rolePermissions = Substitute.For<IRolePermissionRepository>();

    private AdminScopeService Scopes =>
        new(_users, _members, _bindings, _roles, _roleMenus, _menus, _rolePermissions);

    private RoleVisibilityService Sut =>
        new(Scopes, new ActiveUserRoleReader(_members, _bindings, _roles));

    private static readonly Role CompanyAdmin = Fixtures.Role(90, "company_admin", isAdmin: true);
    private static readonly Role ProductOp = Fixtures.Role(91, "product_op", parentRoleId: 90);
    private static readonly Role OtherTenantRole = Fixtures.Role(
        92, "c2_custom", ownerType: RoleOwnerTypes.Company, ownerCode: "C2", parentRoleId: 90);
    private static readonly Role OwnTenantRole = Fixtures.Role(
        93, "c1_custom", ownerType: RoleOwnerTypes.Company, ownerCode: "C1", parentRoleId: 90);

    private static readonly IReadOnlyList<Role> Catalogue = [CompanyAdmin, ProductOp, OtherTenantRole, OwnTenantRole];

    [Fact]
    public async Task AnAbsentCallerSeesNothingRatherThanEverything()
    {
        var visible = await Sut.ResolveVisibleRoleIdsAsync(
            new FakeCaller { UserId = 0 }, Catalogue, CancellationToken.None);

        visible.ShouldNotBeNull("null would mean unrestricted, which is how this endpoint leaks");
        visible.ShouldBeEmpty();
    }

    [Fact]
    public async Task ThePlatformOwnerIsUnrestricted()
    {
        Flags(1, true);

        var visible = await Sut.ResolveVisibleRoleIdsAsync(
            new FakeCaller { UserId = 1 }, Catalogue, CancellationToken.None);

        visible.ShouldBeNull();
    }

    [Fact]
    public async Task ATenantSeesItsOwnRolesButNotAnotherTenantsUnderTheSharedLeader()
    {
        Flags(5, false);
        var caller = FakeCaller.Tenant(5, TenantTypes.Company, "C1").Holding(
            scopes: new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
            {
                [TenantTypes.Company] = new(["C1"], false),
            });

        _members.ListActiveByUserAsync(5, Arg.Any<CancellationToken>())
            .Returns([Fixtures.Membership(1, 5, TenantTypes.Company, "C1", isAdmin: true)]);
        _bindings.ListRoleIdsByMemberIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(new Dictionary<int, IReadOnlyList<int>> { [1] = [90] });
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([CompanyAdmin]);

        var visible = await Sut.ResolveVisibleRoleIdsAsync(caller, Catalogue, CancellationToken.None);

        visible.ShouldNotBeNull();
        visible.ShouldContain(90, "the caller holds it");
        visible.ShouldContain(91, "a platform role filed under a role they hold");
        visible.ShouldContain(93, "their own tenant's role, reached through the scope envelope");
        visible.ShouldNotContain(
            92, "another company's role under the same shared leader must not be revealed");
    }

    [Fact]
    public async Task WholeDimensionBreadthDoesNotOpenOtherTenantsRoles()
    {
        Flags(5, false);

        // "All companies" as data breadth, and nothing else.
        var caller = FakeCaller.Global(5, TenantTypes.Company).Holding(
            scopes: new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
            {
                [TenantTypes.Company] = ScopeClaim.Global,
            });

        _members.ListActiveByUserAsync(5, Arg.Any<CancellationToken>()).Returns([]);

        var visible = await Sut.ResolveVisibleRoleIdsAsync(caller, Catalogue, CancellationToken.None);

        visible.ShouldNotBeNull();
        visible.ShouldBeEmpty("is_global is deliberately not honoured as authority over role definitions");
    }

    [Fact]
    public async Task ACompanyContextDoesNotSeeSupplierRolesThroughAMountedSupplier()
    {
        Flags(5, false);
        var supplierRole = Fixtures.Role(
            94, "s1_custom", ownerType: RoleOwnerTypes.Supplier, ownerCode: "S1",
            category: RoleCategories.Supplier);

        var caller = FakeCaller.Tenant(5, TenantTypes.Company, "C1").Holding(
            scopes: new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
            {
                [TenantTypes.Company] = new(["C1"], false),
                [TenantTypes.Supplier] = new(["S1"], false),
            });

        _members.ListActiveByUserAsync(5, Arg.Any<CancellationToken>()).Returns([]);

        var visible = await Sut.ResolveVisibleRoleIdsAsync(
            caller, [.. Catalogue, supplierRole], CancellationToken.None);

        visible.ShouldNotBeNull();
        visible.ShouldNotContain(94, "the company context is locked to the company dimension");
        visible.ShouldContain(93);
    }

    [Fact]
    public async Task WritingAnotherTenantsRoleIsRefusedWith403()
    {
        Flags(5, false);
        var caller = FakeCaller.Tenant(5, TenantTypes.Company, "C1");

        var ex = await Should.ThrowAsync<ForbiddenException>(
            () => Sut.AssertRoleVisibleAsync(caller, OtherTenantRole, mutate: true, CancellationToken.None));

        ex.StatusCode.ShouldBe(403, "a soft 200 here would tell the client the write succeeded");
    }

    [Fact]
    public async Task ReadingATenantRoleIsAllowedWhenTheEnvelopeCoversItsOwner()
    {
        Flags(5, false);
        var caller = FakeCaller.Tenant(5, TenantTypes.Company, "C1").Holding(
            scopes: new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
            {
                [TenantTypes.Company] = new(["C1", "C2"], false),
            });

        await Sut.AssertRoleVisibleAsync(caller, OtherTenantRole, mutate: false, CancellationToken.None);
    }

    [Fact]
    public async Task AGlobalCallerCannotOpenATenantRoleOutsideItsEnvelope()
    {
        Flags(5, false);
        var caller = FakeCaller.Global(5, TenantTypes.Company);

        var ex = await Should.ThrowAsync<ForbiddenException>(
            () => Sut.AssertRoleVisibleAsync(caller, OtherTenantRole, mutate: false, CancellationToken.None));

        ex.StatusCode.ShouldBe(403);
    }

    [Fact]
    public async Task ATenantMayReadButNotEditAPlatformRole()
    {
        Flags(5, false);
        var caller = FakeCaller.Tenant(5, TenantTypes.Company, "C1");

        await Sut.AssertRoleVisibleAsync(caller, CompanyAdmin, mutate: false, CancellationToken.None);

        await Should.ThrowAsync<ForbiddenException>(
            () => Sut.AssertRoleVisibleAsync(caller, CompanyAdmin, mutate: true, CancellationToken.None));
    }

    [Fact]
    public void OnlyTenantOwnedRolesAreWritableByATenantScope()
    {
        var scope = AdminScope.Empty();

        RoleVisibilityService.RoleWritableByScope(null, OwnTenantRole).ShouldBeFalse();
        RoleVisibilityService.RoleWritableByScope(AdminScope.ForSuperAdmin(), CompanyAdmin).ShouldBeTrue();
        RoleVisibilityService.RoleWritableByScope(scope, CompanyAdmin)
            .ShouldBeFalse("a platform role is never writable through a tenant scope");
    }

    private void Flags(int userId, bool isSuperAdmin) =>
        _users.FindFlagsAsync(userId, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(userId, BackOfficeUserStatuses.Active, isSuperAdmin, 0));
}
