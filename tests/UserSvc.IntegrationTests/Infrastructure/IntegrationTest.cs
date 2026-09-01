using Xunit;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>Base class that truncates the database and flushes Redis before each test, so tests
/// never inherit each other's rows.</summary>
[Collection(IntegrationTestCollection.Name)]
public abstract class IntegrationTest(ServiceFixture fixture) : IAsyncLifetime
{
    protected ServiceFixture Fixture { get; } = fixture;

    public Task InitializeAsync() => Fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;
}
