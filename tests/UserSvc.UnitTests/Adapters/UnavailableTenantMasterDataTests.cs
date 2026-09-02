using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using UserSvc.Infrastructure.External;
using Xunit;

namespace UserSvc.UnitTests.Adapters;

/// <summary>
/// The two master-data placeholders refuse in different shapes, and the difference is the whole
/// point: one port has a vocabulary for "not reached" and the other does not, so answering the
/// second one at all would be inventing a fact.
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
    /// The supplier-link stand-in degrades instead of refusing, and the reason is where the port
    /// sits rather than what it means. It is read from inside
    /// <c>TenantContextAppService.ComputeAsync</c> - the one funnel every authority decision comes
    /// through - so a throw took down permissions, menus and roles for every caller acting in a
    /// company or supplier context, on endpoints that never read a supplier link. The empty answer
    /// can only narrow a data-scope envelope, never widen one, so it fails closed where the throw
    /// failed open (<c>GET /back-office/me</c> answered <c>menus: null</c>, which the shell reads
    /// as "this backend does not gate menus").
    /// </summary>
    [Fact]
    public async Task TheSupplierLinkDirectoryNarrowsTheEnvelopeRatherThanFailingTheRequest()
    {
        var directory = new UnavailableSupplierCompanyLinkDirectory(
            NullLogger<UnavailableSupplierCompanyLinkDirectory>.Instance);

        (await directory.ListSupplierCodesByCompanyAsync("C001", CancellationToken.None))
            .ShouldBeEmpty();

        (await directory.FindCompanyCodeBySupplierAsync("S9", CancellationToken.None))
            .ShouldBeNull();
    }
}
