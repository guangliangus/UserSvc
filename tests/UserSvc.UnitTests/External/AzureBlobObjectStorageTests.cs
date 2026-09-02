using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.External;
using UserSvc.Infrastructure.External;
using Xunit;

namespace UserSvc.UnitTests.External;

/// <summary>
/// The Azure Blob adapter, as far as it can be exercised without a storage account: the shape of
/// its refusal when this deployment has none, and its option validator.
/// <para>
/// It lived in <c>Profile/AvatarAppServiceTests.cs</c> as a second public class until wave 8 - a
/// file named after an application service, so a search for the adapter's own tests found nothing
/// and the two subjects shared one set of <c>using</c> directives. It is here now because this is
/// where the other <c>UserSvc.Infrastructure.External</c> adapter tests are, and one public test
/// class per file named after its subject is what makes them findable.
/// </para>
/// <para>
/// What is <b>not</b> here: the mapping from Azure's own failures onto 502 and 500. That needs a
/// real endpoint to fail, so it was verified out-of-band against the live service - an account host
/// that does not resolve produces an <c>AggregateException</c> of six <c>RequestFailedException</c>s
/// with status 0 and comes back 502 <c>UPSTREAM_SERVICE_UNAVAILABLE</c> in under two seconds; a
/// wrong key produces a bare 403 and comes back 500 <c>INTERNAL_ERROR</c>. An integration test with
/// Azurite is the way to keep it honest.
/// </para>
/// </summary>
public sealed class AzureBlobObjectStorageTests
{
    private static readonly ObjectHttpHeaders Headers = new("image/png", "public, max-age=31536000", "inline");

    [Fact]
    public async Task WithNoConnectionStringTheAdapterStillConstructsAndRefusesOnlyWhenUsed()
    {
        // The whole point of the per-request refusal: building the adapter - which happens while
        // the DI container is being built, for every deployment - must not throw. If it did, a
        // service with no blob account could not sign anyone in either.
        var storage = new AzureBlobObjectStorage(
            Options.Create(new AzureBlobOptions()),
            NullLogger<AzureBlobObjectStorage>.Instance);

        var ex = await Should.ThrowAsync<AppException>(
            () => storage.PutAsync("7/1.png", new MemoryStream([1, 2, 3]), Headers, CancellationToken.None));

        // 500 NOT_CONFIGURED and not 501 NOT_IMPLEMENTED: the code is all here and a value is
        // absent, which is the distinction ErrorCodes.NotConfigured is defined by. Every other
        // missing secret in this service answers the same way.
        ex.StatusCode.ShouldBe(500);
        ex.ErrorCode.ShouldBe(ErrorCodes.NotConfigured);

        // And the detail names the section and the key - the whole point of the code - while never
        // quoting a value, because there is no value to quote on this deployment.
        ex.Message.ShouldContain($"{AzureBlobOptions.SectionName}:{nameof(AzureBlobOptions.ConnectionString)}");
    }

    [Fact]
    public async Task ADeleteOnADeploymentWithNoStorageSucceedsInsteadOfRefusing()
    {
        // Not symmetrical with PutAsync's refusal, on purpose. Every caller of DeleteAsync is
        // unwinding some other failure; a NOT_CONFIGURED thrown here would surface instead of the
        // reason the request actually failed. Nothing was ever stored on such a deployment, so "it
        // is gone" is true.
        var storage = new AzureBlobObjectStorage(
            Options.Create(new AzureBlobOptions()),
            NullLogger<AzureBlobObjectStorage>.Instance);

        await storage.DeleteAsync("feedback/7/whatever.png", CancellationToken.None);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ADeleteOfABlankNameIsANoOpRatherThanAnArgumentException(string objectName)
    {
        // A cleanup loop over names it did not manage to record must not blow up on an empty one.
        var storage = new AzureBlobObjectStorage(
            Options.Create(new AzureBlobOptions
            {
                ConnectionString =
                    "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=c2VjcmV0MTIz;EndpointSuffix=core.windows.net",
            }),
            NullLogger<AzureBlobObjectStorage>.Instance);

        // Reaches no network: the blank name is refused before the container client is touched.
        await storage.DeleteAsync(objectName, CancellationToken.None);
    }

    [Fact]
    public void AnAbsentConnectionStringIsALegalDeployment() =>
        Validate(new AzureBlobOptions()).ShouldBeEmpty();

    [Fact]
    public void AConnectionStringThatIsPresentButMalformedFailsTheBootWithoutEchoingItself()
    {
        const string secret = "SUPERSECRETKEY123==";

        var results = Validate(new AzureBlobOptions
        {
            ConnectionString = $"DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={secret};trailing",
        });

        var failure = results.ShouldHaveSingleItem();
        failure.MemberNames.ShouldContain(nameof(AzureBlobOptions.ConnectionString));

        // Present-and-malformed is a mistake, so it is caught at startup - but a startup failure is
        // a log line, and a log line must not contain a storage key.
        failure.ErrorMessage.ShouldNotBeNull();
        failure.ErrorMessage.ShouldNotContain(secret);
        failure.ErrorMessage.ShouldNotContain("AccountKey");
    }

    [Fact]
    public void AWellFormedConnectionStringPassesWithoutTouchingTheNetwork() =>
        Validate(new AzureBlobOptions
        {
            ConnectionString =
                "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=c2VjcmV0MTIz;EndpointSuffix=core.windows.net",
        }).ShouldBeEmpty();

    [Theory]
    // Azure's own container rules. Each of these would otherwise surface as a 400 from the storage
    // service on every single upload, arriving as a 500 about a container nobody thought to check.
    [InlineData("us")]
    [InlineData("Users")]
    [InlineData("-users")]
    [InlineData("users-")]
    [InlineData("us--ers")]
    [InlineData("users_1")]
    public void AContainerNameAzureWouldRefuseFailsTheBoot(string name) =>
        Validate(new AzureBlobOptions { ContainerName = name })
            .ShouldContain(r => r.MemberNames.Contains(nameof(AzureBlobOptions.ContainerName)));

    [Fact]
    public void TheDefaultsAreTheOnesTheDeploymentNotesPromise()
    {
        var options = new AzureBlobOptions();

        options.ContainerName.ShouldBe("users");
        options.MaxRetryAttempts.ShouldBe(2);
        options.AttemptTimeout.ShouldBe(TimeSpan.FromSeconds(10));
    }

    /// <summary>Runs the section exactly as <c>ValidateDataAnnotations</c> does - attributes and
    /// <see cref="IValidatableObject"/> together, which is what the startup validator invokes.</summary>
    private static List<ValidationResult> Validate(AzureBlobOptions options)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(options, new ValidationContext(options), results, validateAllProperties: true);
        return results;
    }
}
