using System.Xml.Linq;
using Shouldly;
using Xunit;

namespace UserSvc.ArchitectureTests;

/// <summary>
/// Reads the project files directly, closing a real blind spot in <see cref="DependencyRuleTests"/>:
/// <c>Assembly.GetReferencedAssemblies()</c> only reports assemblies <b>actually used</b> in the
/// emitted IL, so adding a <c>PackageReference</c> without writing any code against it leaves the
/// reference trimmed and invisible at runtime.
/// <para>
/// "Added but not used yet" is precisely the moment worth catching in review — once a package sits
/// in the project, someone will eventually use it. So this layer inspects the source of truth
/// rather than the build output.
/// </para>
/// </summary>
public sealed class PackageReferenceTests
{
    /// <summary>Decision 15: EF only. No project may take a second data-access stack.</summary>
    private static readonly string[] BannedEverywhere = ["Dapper", "Dapper.Contrib"];

    /// <summary>Decision 03: these two are the inner rings and know no technology choices.</summary>
    private static readonly string[] InnerRingProjects = ["UserSvc.Domain", "UserSvc.Application"];

    private static readonly string[] BannedInInnerRing =
    [
        "Microsoft.EntityFrameworkCore",
        "Npgsql",
        "StackExchange.Redis",
        "RabbitMQ.Client",
        "Microsoft.AspNetCore",
        "Serilog",
    ];

    [Fact]
    public void InnerRingProjectsDeclareNoInfrastructurePackages()
    {
        foreach (var project in SourceProjects().Where(p => InnerRingProjects.Contains(ProjectName(p))))
        {
            var offenders = PackageReferences(project)
                .Where(p => BannedInInnerRing.Any(b => p.StartsWith(b, StringComparison.Ordinal)))
                .ToArray();

            offenders.ShouldBeEmpty(
                $"{ProjectName(project)} is an inner ring — it must not declare {string.Join(", ", offenders)}. " +
                "Put the adapter in UserSvc.Infrastructure and define a port instead.");
        }
    }

    [Fact]
    public void NoProjectDeclaresASecondDataAccessStack()
    {
        foreach (var project in SourceProjects())
        {
            var offenders = PackageReferences(project)
                .Where(p => BannedEverywhere.Contains(p, StringComparer.Ordinal))
                .ToArray();

            offenders.ShouldBeEmpty(
                $"{ProjectName(project)} must not take {string.Join(", ", offenders)}. " +
                "It does not join the EF transaction and bypasses the global query filters " +
                "(soft delete, tenant isolation). Use EF's SqlQuery/FromSql/ExecuteSql for raw SQL. " +
                "See docs/architecture.md before changing this rule.");
        }
    }

    [Fact]
    public void DomainDeclaresNoPackagesAtAll()
    {
        var domain = SourceProjects().Single(p => ProjectName(p) == "UserSvc.Domain");

        PackageReferences(domain).ShouldBeEmpty(
            "Domain is the innermost ring. A package there is a design decision worth arguing about " +
            "in review — not something that lands by accident.");
    }

    internal static IEnumerable<string> SourceProjects() =>
        Directory.EnumerateFiles(Path.Combine(RepositoryRoot(), "src"), "*.csproj", SearchOption.AllDirectories);

    private static string ProjectName(string projectPath) => Path.GetFileNameWithoutExtension(projectPath);

    private static string[] PackageReferences(string projectPath) =>
        [.. XDocument.Load(projectPath)
            .Descendants("PackageReference")
            .Select(e => e.Attribute("Include")?.Value ?? string.Empty)
            .Where(v => v.Length > 0)];

    internal static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "UserSvc.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
               ?? throw new InvalidOperationException("Could not locate the repository root (UserSvc.slnx).");
    }
}
