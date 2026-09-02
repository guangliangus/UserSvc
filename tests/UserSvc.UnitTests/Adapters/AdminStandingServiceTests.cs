using NSubstitute;
using Shouldly;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;
using UserSvc.Infrastructure.BackOffice;
using Xunit;

namespace UserSvc.UnitTests.Adapters;

/// <summary>
/// Gate R3, as the tenant slice asks it: about an account id, with no acting context, from the
/// database every time. The cases below are the ones where a shortcut would have been wrong.
/// </summary>
public sealed class AdminStandingServiceTests
{
    private readonly IBackOfficeUserDirectory _users = Substitute.For<IBackOfficeUserDirectory>();

    private readonly ITenantMemberRepository _members = Substitute.For<ITenantMemberRepository>();

    private AdminStandingService Sut => new(_users, _members);

    private static TenantMember Member(
        string tenantCode, bool isAdmin = true, bool scopeAll = false,
        string tenantType = TenantTypes.Company) =>
        new()
        {
            Id = 900,
            UserId = 57,
            TenantType = tenantType,
            TenantCode = tenantCode,
            IsAdmin = isAdmin,
            ScopeAll = scopeAll,
            Status = TenantMemberStatuses.Active,
        };

    private void Flags(bool isSuperAdmin) =>
        _users.FindFlagsAsync(57, Arg.Any<CancellationToken>())
            .Returns(new BackOfficeUserFlags(57, UserSvc.Domain.Iam.BackOfficeUserStatuses.Active, isSuperAdmin, 1));

    private void Holds(params TenantMember[] memberships) =>
        _members.ListActiveByUserAsync(57, Arg.Any<CancellationToken>()).Returns(memberships);

    /// <summary>A malformed question gets the safe answer, and no round trip.</summary>
    [Fact]
    public async Task ANonPositiveIdIsNotASuperAdministratorAndAdministersNothing()
    {
        (await Sut.IsPlatformSuperAdminAsync(0, CancellationToken.None)).ShouldBeFalse();
        (await Sut.CanManageMembersAsync(0, TenantTypes.Company, "C001", CancellationToken.None))
            .ShouldBeFalse();

        await _users.DidNotReceiveWithAnyArgs().FindFlagsAsync(default, default);
    }

    /// <summary>An unknown id has no standing. That is a "no", not an error.</summary>
    [Fact]
    public async Task AnAccountWithNoRowIsNotASuperAdministrator()
    {
        _users.FindFlagsAsync(57, Arg.Any<CancellationToken>()).Returns((BackOfficeUserFlags?)null);

        (await Sut.IsPlatformSuperAdminAsync(57, CancellationToken.None)).ShouldBeFalse();
    }

    /// <summary>The platform identity holds with zero memberships, so the membership table is never
    /// consulted on this path.</summary>
    [Fact]
    public async Task ThePlatformSuperAdministratorManagesEveryTenantWithoutHoldingAMembership()
    {
        Flags(isSuperAdmin: true);

        (await Sut.CanManageMembersAsync(57, TenantTypes.Company, "C001", CancellationToken.None))
            .ShouldBeTrue();

        await _members.DidNotReceiveWithAnyArgs().ListActiveByUserAsync(default, default);
    }

    [Fact]
    public async Task AnAdministratorOfTheNamedTenantManagesIt()
    {
        Flags(isSuperAdmin: false);
        Holds(Member("C001"));

        (await Sut.CanManageMembersAsync(57, TenantTypes.Company, "C001", CancellationToken.None))
            .ShouldBeTrue();
    }

    /// <summary>The whole-dimension row names no tenant, and covering every company is exactly what
    /// it is for. Reading the sentinel code as a tenant code would refuse it.</summary>
    [Fact]
    public async Task AWholeDimensionAdministratorManagesEveryTenantOfThatDimension()
    {
        Flags(isSuperAdmin: false);
        Holds(Member(TenantScopes.ScopeAllSentinelCode, scopeAll: true));

        (await Sut.CanManageMembersAsync(57, TenantTypes.Company, "C001", CancellationToken.None))
            .ShouldBeTrue();
    }

    /// <summary>Breadth is not authority across dimensions: "every company" says nothing about
    /// suppliers.</summary>
    [Fact]
    public async Task AWholeCompanyDimensionRowDoesNotReachASupplier()
    {
        Flags(isSuperAdmin: false);
        Holds(Member(TenantScopes.ScopeAllSentinelCode, scopeAll: true));

        (await Sut.CanManageMembersAsync(57, TenantTypes.Supplier, "S9", CancellationToken.None))
            .ShouldBeFalse();
    }

    /// <summary>Membership is not administration. A plain member of the tenant may read its roster;
    /// they may not rewrite anybody's access.</summary>
    [Fact]
    public async Task APlainMemberOfTheTenantDoesNotManageIt()
    {
        Flags(isSuperAdmin: false);
        Holds(Member("C001", isAdmin: false));

        (await Sut.CanManageMembersAsync(57, TenantTypes.Company, "C001", CancellationToken.None))
            .ShouldBeFalse();
    }

    /// <summary>An administrator of one tenant is nobody in the next one.</summary>
    [Fact]
    public async Task AnAdministratorOfAnotherTenantDoesNotReachThisOne()
    {
        Flags(isSuperAdmin: false);
        Holds(Member("C002"));

        (await Sut.CanManageMembersAsync(57, TenantTypes.Company, "C001", CancellationToken.None))
            .ShouldBeFalse();
    }
}
