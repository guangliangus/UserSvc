using System.Reflection;
using NetArchTest.Rules;
using Shouldly;
using UserSvc.Domain.Abstractions;
using Xunit;

namespace UserSvc.ArchitectureTests;

/// <summary>
/// Type-level conventions that a csproj cannot express: a controller quietly injecting a
/// DbContext, a concrete class sneaking into Ports/, a domain event missing its [EventName].
/// </summary>
public sealed class LayeringConventionTests
{
    [Fact]
    public void ControllersDoNotDependOnPersistence()
    {
        var result = Types.InAssembly(Assemblies.Api)
            .That().ResideInNamespace("UserSvc.Api.Controllers")
            .ShouldNot().HaveDependencyOnAny(
                "UserSvc.Infrastructure.Persistence",
                "Microsoft.EntityFrameworkCore")
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            "Controllers talk to AppServices only. Offenders: " +
            string.Join(", ", result.FailingTypeNames ?? []));
    }

    [Fact]
    public void PortsNamespaceHoldsInterfacesOnly()
    {
        var offenders = Assemblies.Application.GetTypes()
            .Where(t => t.Namespace?.StartsWith("UserSvc.Application.Ports", StringComparison.Ordinal) == true)
            .Where(t => t is { IsInterface: false, IsNested: false })
            // Record DTOs used as port parameters or return values are part of the contract.
            .Where(t => !IsRecord(t))
            .Select(t => t.FullName)
            .ToArray();

        offenders.ShouldBeEmpty(
            "Ports/ holds boundary contracts only. A concrete class there is either an adapter " +
            "(belongs in Infrastructure) or a pure function (belongs beside its feature).");
    }

    [Fact]
    public void DomainEventsDeclareTheirWireName()
    {
        var missing = Assemblies.Domain.GetTypes()
            .Where(t => t is { IsAbstract: false, IsInterface: false })
            .Where(t => typeof(IDomainEvent).IsAssignableFrom(t))
            .Where(t => t.GetCustomAttribute<EventNameAttribute>() is null)
            .Select(t => t.FullName)
            .ToArray();

        missing.ShouldBeEmpty(
            "The wire name is a contract and must survive class renames. Add [EventName(\"x.y.v1\")].");
    }

    [Fact]
    public void DomainTypesCarryNoSerializationOrPersistenceAttributes()
    {
        var offenders = Assemblies.Domain.GetTypes()
            .SelectMany(t => t.GetProperties())
            .Where(p => p.GetCustomAttributes()
                .Any(a => a.GetType().Namespace?.StartsWith("System.Text.Json", StringComparison.Ordinal) == true
                          || a.GetType().Namespace?.StartsWith("System.ComponentModel.DataAnnotations.Schema", StringComparison.Ordinal) == true))
            .Select(p => $"{p.DeclaringType?.Name}.{p.Name}")
            .ToArray();

        offenders.ShouldBeEmpty(
            "JSON shape and table shape are delivery details — keep them in the adapters.");
    }

    private static bool IsRecord(Type type) =>
        type.GetMethod("<Clone>$", BindingFlags.Public | BindingFlags.Instance) is not null;
}
