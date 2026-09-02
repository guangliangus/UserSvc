using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using UserSvc.Infrastructure.External;
using Xunit;

namespace UserSvc.UnitTests.Adapters;

/// <summary>
/// The last refusing placeholder in the service. The company and supplier registers belong to the
/// product master data, which is somebody else's tables, so this one cannot be replaced by reading
/// our own database - unlike the supplier-link stand-in that used to be tested beside it, which
/// the real repository replaced in wave 6 and which has now been deleted rather than left lying
/// around unregistered.
/// <para>
/// What is pinned here is the <i>shape</i> of the refusal: this port has a vocabulary for "could
/// not be reached", and answering anything else would be inventing a fact.
/// </para>
/// </summary>
public sealed class UnavailableTenantMasterDataTests
{
    /// <summary>Null is this port's own word for "could not be reached", and every caller is
    /// written to fall open on it. Returning entries would mean inventing a Usable verdict.</summary>
    [Fact]
    public async Task TheMasterDataDirectoryReportsNotReachedRatherThanInventingAVerdict()
    {
        var directory = new UnavailableTenantMasterDataDirectory(
            NullLogger<UnavailableTenantMasterDataDirectory>.Instance);

        (await directory.ValidateAsync(["C001"], ["S9"], CancellationToken.None)).ShouldBeNull();
    }

    /// <summary>
    /// Constructing it reads no configuration and touches nothing, which is what lets it be
    /// registered on every deployment: a placeholder that could fail while being built would take
    /// out the container rather than the capability it stands in for.
    /// </summary>
    [Fact]
    public void ConstructingItReadsNothing() =>
        Should.NotThrow(() => new UnavailableTenantMasterDataDirectory(
            NullLogger<UnavailableTenantMasterDataDirectory>.Instance));
}
