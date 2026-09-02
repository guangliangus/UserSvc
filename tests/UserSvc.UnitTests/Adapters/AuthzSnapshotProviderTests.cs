using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;
using StackExchange.Redis;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Iam;
using UserSvc.Infrastructure.BackOffice;
using UserSvc.Infrastructure.Platform;
using Xunit;

// The two IAM slices each declare a TenantTypes and a ScopeClaim; the cached snapshot uses the
// tenancy pair, because that is what the context funnel produces.
using ScopeClaim = UserSvc.Domain.Tenancy.ScopeClaim;
using TenantTypes = UserSvc.Domain.Tenancy.TenantTypes;

namespace UserSvc.UnitTests.Adapters;

/// <summary>
/// The route map is the one part of the snapshot adapter that decides anything, and each rule it
/// applies exists because the alternative broke something visible in the front end.
/// </summary>
public sealed class AuthzSnapshotProviderTests
{
    private readonly IMenuRepository _menus = Substitute.For<IMenuRepository>();

    private static Menu Menu(string code, string? path, string status = MenuStatuses.Active) =>
        new() { Id = code.Length, Code = code, Path = path, Status = status };

    private AuthzSnapshotProvider Sut => new(
        new TenantContextAppService(
            Substitute.For<ITenantMemberRepository>(),
            Substitute.For<IUserTenantRoleRepository>(),
            Substitute.For<IRoleDirectory>(),
            Substitute.For<IRbacCatalog>(),
            Substitute.For<IAdminStandingService>(),
            Substitute.For<IBackOfficeAccountDirectory>(),
            Substitute.For<ISupplierCompanyLinkDirectory>()),
        Substitute.For<IBackendUserRepository>(),
        _menus,
        new RedisAuthzSnapshotCache(
            Substitute.For<IConnectionMultiplexer>(),
            Options.Create(new RedisOptions { Configuration = "localhost:6379", KeyPrefix = "test:" }),
            NullLogger<RedisAuthzSnapshotCache>.Instance),
        NullLogger<AuthzSnapshotProvider>.Instance);

    /// <summary>An empty ask is answered without a round trip, and with a list rather than a null -
    /// null means "could not be resolved" on this method and would send the front end to its
    /// fallback map for no reason.</summary>
    [Fact]
    public async Task NoCodesAnswersAnEmptyListWithoutReadingAnything()
    {
        var routes = await Sut.MenuRoutesForCodesAsync([], CancellationToken.None);

        routes.ShouldNotBeNull();
        routes.ShouldBeEmpty();
        await _menus.DidNotReceiveWithAnyArgs().ListByCodesAsync(default!, default);
    }

    [Fact]
    public async Task InactiveMenusAndRoutelessContainersAreLeftOut()
    {
        _menus.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([
                Menu("retired", "/retired", MenuStatuses.Inactive),
                Menu("group", "   "),
                Menu("orders", "/orders"),
            ]);

        var routes = await Sut.MenuRoutesForCodesAsync(["retired", "group", "orders"], CancellationToken.None);

        routes.ShouldNotBeNull();
        routes.Select(route => route.Code).ShouldBe(["orders"]);
    }

    /// <summary>A malformed path is dropped rather than passed on: a missing pair fails closed and
    /// is noticed at once, while a bad one points the route gate at a page that does not exist.</summary>
    [Theory]
    [InlineData("orders")]
    [InlineData("/or ders")]
    [InlineData("/orders|extra")]
    public async Task MalformedPathsAreDropped(string path)
    {
        _menus.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([Menu("orders", path)]);

        (await Sut.MenuRoutesForCodesAsync(["orders"], CancellationToken.None)).ShouldBeEmpty();
    }

    [Fact]
    public async Task TrailingSlashesAreTrimmedButTheRootPathSurvives()
    {
        _menus.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([Menu("zulu", "/"), Menu("alpha", "/orders/")]);

        var routes = await Sut.MenuRoutesForCodesAsync(["zulu", "alpha"], CancellationToken.None);

        // Sorted by code, so two calls with the same grant answer byte-identically.
        routes.ShouldNotBeNull();
        routes.Select(route => (route.Code, route.Path)).ShouldBe([("alpha", "/orders"), ("zulu", "/")]);
    }

    /// <summary>A read failure reports "not delivered" rather than "you route nowhere". The two
    /// look alike in JSON and mean opposite things to the shell.</summary>
    [Fact]
    public async Task AFailedReadAnswersNullRatherThanAnEmptyMap()
    {
        _menus.ListByCodesAsync(Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns<IReadOnlyList<Menu>>(_ => throw new InvalidOperationException("no database"));

        (await Sut.MenuRoutesForCodesAsync(["orders"], CancellationToken.None)).ShouldBeNull();
    }

    /// <summary>
    /// The cached entry has to survive a round trip through Redis, and the two collection shapes in
    /// it are exactly the ones System.Text.Json can refuse to rebuild. A snapshot that serialises
    /// but does not deserialise would look like a permanent cache miss and quietly cost a full
    /// recomputation on every request.
    /// </summary>
    [Fact]
    public void ACachedSnapshotSurvivesAJsonRoundTrip()
    {
        var original = new CachedAuthzSnapshot(
            7,
            ["company_admin"],
            ["uam.member.read"],
            ["orders"],
            new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)
            {
                [TenantTypes.Company] = new(["C001"], false),
                [TenantTypes.Supplier] = ScopeClaim.Global,
            });

        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        var restored = JsonSerializer.Deserialize<CachedAuthzSnapshot>(
            JsonSerializer.Serialize(original, options), options);

        restored.ShouldNotBeNull();
        restored.Ver.ShouldBe(7);
        restored.Roles.ShouldBe(["company_admin"]);
        restored.Permissions.ShouldBe(["uam.member.read"]);
        restored.Menus.ShouldBe(["orders"]);
        restored.Scopes[TenantTypes.Company].Values.ShouldBe(["C001"]);
        restored.Scopes[TenantTypes.Company].IsGlobal.ShouldBeFalse();
        restored.Scopes[TenantTypes.Supplier].IsGlobal.ShouldBeTrue();
    }
}
