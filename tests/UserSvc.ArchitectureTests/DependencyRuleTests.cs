using System.Reflection;
using Shouldly;
using Xunit;

namespace UserSvc.ArchitectureTests;

/// <summary>
/// Decisions 03 and 06: the <b>bedrock</b> dependency-rule tests.
/// <para>
/// These read the assembly reference table directly and depend on no third-party architecture
/// library, which makes them the layer least likely to rot. ProjectReference in the csproj already
/// blocks coarse violations, but not transitive ones — Application picking up EntityFrameworkCore
/// through some package, say — and that is the hole these close.
/// </para>
/// <para>
/// Note the blind spot they cannot cover: <see cref="Assembly.GetReferencedAssemblies"/> only lists
/// assemblies actually used in the emitted IL, so a PackageReference nobody has written code
/// against yet is invisible here. <see cref="PackageReferenceTests"/> covers that case by reading
/// the project files instead.
/// </para>
/// </summary>
public sealed class DependencyRuleTests
{
    private static readonly string[] InfrastructureConcerns =
    [
        "Microsoft.EntityFrameworkCore",
        "Npgsql",
        "StackExchange.Redis",
        "Microsoft.AspNetCore",
        "RabbitMQ",
    ];

    [Fact]
    public void DomainReferencesNoInfrastructure()
    {
        var offenders = ReferencedNames(Assemblies.Domain)
            .Where(name => InfrastructureConcerns.Any(c => name.StartsWith(c, StringComparison.Ordinal)))
            .ToArray();

        offenders.ShouldBeEmpty(
            $"Domain must stay free of infrastructure. Offending references: {string.Join(", ", offenders)}");
    }

    [Fact]
    public void DomainReferencesNoOuterRing()
    {
        ReferencedNames(Assemblies.Domain)
            .Where(n => n.StartsWith("UserSvc.", StringComparison.Ordinal))
            .ShouldBeEmpty("Domain is the innermost ring — it references nothing of ours.");
    }

    [Fact]
    public void ApplicationReferencesNoInfrastructureTechnology()
    {
        var offenders = ReferencedNames(Assemblies.Application)
            .Where(name => InfrastructureConcerns.Any(c => name.StartsWith(c, StringComparison.Ordinal)))
            .ToArray();

        offenders.ShouldBeEmpty(
            "Application defines ports; it must not know how they are implemented. " +
            $"Offending references: {string.Join(", ", offenders)}");
    }

    [Fact]
    public void ApplicationReferencesDomainOnly()
    {
        ReferencedNames(Assemblies.Application)
            .Where(n => n.StartsWith("UserSvc.", StringComparison.Ordinal))
            .ShouldBe(["UserSvc.Domain"]);
    }

    [Fact]
    public void InfrastructureDoesNotReferenceTheHost()
    {
        ReferencedNames(Assemblies.Infrastructure)
            .ShouldNotContain("UserSvc.Api", "Dependencies point inward, never at the host.");
    }

    /// <summary>Decision 15: EF only. No project may take a second data-access stack.</summary>
    [Fact]
    public void NoAssemblyUsesDapper()
    {
        Assembly[] all = [Assemblies.Domain, Assemblies.Application, Assemblies.Infrastructure, Assemblies.Api];

        foreach (var assembly in all)
        {
            ReferencedNames(assembly).ShouldNotContain(
                "Dapper",
                $"{assembly.GetName().Name} must not take a second data-access stack. " +
                "Dapper does not join the EF transaction and bypasses the global query filters " +
                "(soft delete, tenant isolation). Use EF's SqlQuery/FromSql/ExecuteSql for raw SQL.");
        }
    }

    private static string[] ReferencedNames(Assembly assembly) =>
        [.. assembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .Where(n => n.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];
}
