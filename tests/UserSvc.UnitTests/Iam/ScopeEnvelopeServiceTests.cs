using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;
using Xunit;

namespace UserSvc.UnitTests.Iam;

/// <summary>Data breadth: what the envelope says, and what it must never say.</summary>
public sealed class ScopeEnvelopeServiceTests
{
    private readonly IBackOfficeUserDirectory _users = Substitute.For<IBackOfficeUserDirectory>();
    private readonly ITenantMemberDirectory _members = Substitute.For<ITenantMemberDirectory>();
    private readonly IUserTenantRoleRepository _bindings = Substitute.For<IUserTenantRoleRepository>();
    private readonly IRoleRepository _roles = Substitute.For<IRoleRepository>();
    private readonly IRoleMenuRepository _roleMenus = Substitute.For<IRoleMenuRepository>();
    private readonly IMenuRepository _menus = Substitute.For<IMenuRepository>();
    private readonly IRolePermissionRepository _rolePermissions = Substitute.For<IRolePermissionRepository>();

    private ScopeEnvelopeService Sut => new(
        new AdminScopeService(_users, _members, _bindings, _roles, _roleMenus, _menus, _rolePermissions),
        _members);

    [Fact]
    public async Task ThePlatformOwnerIsGlobalInBothDimensionsWithoutAnyMembership()
    {
        _users.FindFlagsAsync(1, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(1, BackOfficeUserStatuses.Active, true, 0));

        var envelope = await Sut.LoadUserScopeClaimsAsync(1, CancellationToken.None);

        envelope[TenantTypes.Company].IsGlobal.ShouldBeTrue();
        envelope[TenantTypes.Supplier].IsGlobal.ShouldBeTrue();
        envelope[TenantTypes.Company].Values.ShouldBeEmpty(
            "global carries an empty list, never null, so a consumer reads 'everything' not 'missing'");
    }

    [Fact]
    public void AWholeDimensionRowOverridesEverySpecificRowOnItsSide()
    {
        var envelope = ScopeEnvelopeService.Aggregate(5,
        [
            Fixtures.Membership(1, 5, TenantTypes.Company, "C1"),
            Fixtures.Membership(2, 5, TenantTypes.Company, IamConstants.ScopeAllSentinelCode, scopeAll: true),
            Fixtures.Membership(3, 5, TenantTypes.Supplier, "S2"),
        ]);

        envelope[TenantTypes.Company].IsGlobal.ShouldBeTrue();
        envelope[TenantTypes.Company].Values.ShouldBeEmpty("the sentinel is never a value");
        envelope[TenantTypes.Supplier].Values.ShouldBe(["S2"]);
    }

    [Fact]
    public void ValuesAreTrimmedDeduplicatedAndSorted()
    {
        var envelope = ScopeEnvelopeService.Aggregate(5,
        [
            Fixtures.Membership(1, 5, TenantTypes.Company, " C2 "),
            Fixtures.Membership(2, 5, TenantTypes.Company, "C1"),
            Fixtures.Membership(3, 5, TenantTypes.Company, "C1"),
        ]);

        envelope[TenantTypes.Company].Values.ShouldBe(["C1", "C2"]);
    }

    [Fact]
    public void AnUnknownDimensionIsLoudRatherThanSilentlyDropped()
    {
        Should.Throw<BadRequestException>(() => ScopeEnvelopeService.Aggregate(5,
            [Fixtures.Membership(1, 5, "warehouse", "W1")]));
    }

    [Fact]
    public void AnAccountWithNoMembershipsHasNoDimensions()
    {
        ScopeEnvelopeService.Aggregate(5, []).ShouldBeEmpty();
    }

    [Fact]
    public void TheEmptyEnvelopeDeclaresBothDimensionsExplicitly()
    {
        var empty = ScopeEnvelopeService.Empty();

        empty.Count.ShouldBe(2);
        empty[TenantTypes.Company].IsGlobal.ShouldBeFalse();
        empty[TenantTypes.Supplier].Values.ShouldBeEmpty();
    }

    [Fact]
    public void TheWireShapeFollowsTheFixedDimensionOrder()
    {
        var scopes = ScopeEnvelopeService.BuildUserScopes(ScopeEnvelopeService.AllGlobal());

        scopes.Select(scope => scope.ScopeType).ShouldBe([TenantTypes.Supplier, TenantTypes.Company]);
        scopes.ShouldAllBe(scope => scope.IsGlobal);
    }
}
