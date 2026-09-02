using Shouldly;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Domain.Tenancy;
using Xunit;
using static UserSvc.UnitTests.Tenancy.TenantTestData;

namespace UserSvc.UnitTests.Tenancy;

/// <summary>Menu resolution: what survives the catalogue, and what comes along with it.</summary>
public sealed class TenantMenuResolverTests
{
    [Fact]
    public void AGrantedChildBringsItsWholeAncestryAlong()
    {
        // Otherwise a granted page renders with no group to sit under, which is not a menu.
        var menus = new[]
        {
            Menu(1, "order"),
            Menu(2, "order.sub", parentId: 1),
            Menu(3, "order.sub.leaf", parentId: 2),
        };

        var (codes, keptIds) = TenantMenuResolver.Resolve([3], menus, TenantTypes.Company);

        codes.ShouldBe(["order", "order.sub", "order.sub.leaf"]);
        keptIds.ShouldBe(new HashSet<int> { 1, 2, 3 }, ignoreOrder: true);
    }

    [Fact]
    public void AGrantedMenuThatIsNoLongerActiveSimplyDisappears()
    {
        var (codes, keptIds) = TenantMenuResolver.Resolve([1, 2], [Menu(1, "order")], TenantTypes.Company);

        codes.ShouldBe(["order"]);
        keptIds.ShouldNotContain(2, "and its permission points fall with it");
    }

    [Fact]
    public void GrantingNothingResolvesToNothing()
    {
        var (codes, keptIds) = TenantMenuResolver.Resolve([], [Menu(1, "order")], TenantTypes.Company);

        codes.ShouldBeEmpty();
        keptIds.ShouldBeEmpty();
    }

    [Fact]
    public void TheAudienceFilterIsCurrentlyOffAndThisIsWhereThatIsRecorded()
    {
        // A supplier-only menu granted to a company context still resolves. That is the state the
        // Go service was in when this was ported and it was deliberate: audience narrows what the
        // sidebar renders, not what may be entered - routes are gated on permission codes.
        // When the filter is restored, this expectation becomes ["order"] and the sibling
        // expectation in the ancestry test becomes the interesting one, because a filtered-out
        // parent must stop contributing its own code while the climb continues past it.
        var menus = new[]
        {
            Menu(1, "order", audience: TenantTypes.Company),
            Menu(2, "supplier_products", audience: TenantTypes.Supplier),
        };

        var (codes, _) = TenantMenuResolver.Resolve([1, 2], menus, TenantTypes.Company);

        codes.ShouldBe(["order", "supplier_products"]);
    }

    [Fact]
    public void ACycleInTheParentChainCannotHangTheResolver()
    {
        // The catalogue has a self-reference check, but this runs on every authorization decision
        // and a data problem must not become an unresponsive service.
        var menus = new[] { Menu(1, "a", parentId: 2), Menu(2, "b", parentId: 1) };

        var (codes, _) = TenantMenuResolver.Resolve([1], menus, TenantTypes.Company);

        codes.ShouldBe(["a", "b"]);
    }
}
