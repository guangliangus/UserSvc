using Xunit;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>
/// Every integration test in this assembly belongs to this one collection, and that is a
/// correctness requirement rather than tidiness. xunit runs collections in parallel but serialises
/// the tests inside one, and the containers plus the truncate-between-tests reset are shared: a
/// second collection would race the reset against another collection's assertions.
/// <para>
/// The class must be public - "xUnit1027: Collection definition classes must be public" is an
/// error at default severity, and a type with no access modifier is internal.
/// </para>
/// </summary>
[CollectionDefinition(Name)]
public sealed class IntegrationTestCollection : ICollectionFixture<ServiceFixture>
{
    public const string Name = "usersvc-integration";
}
