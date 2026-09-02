using Shouldly;
using UserSvc.Application.Features.BackOffice.Suppliers;
using Xunit;

namespace UserSvc.UnitTests.Suppliers;

/// <summary>
/// The query-string rules. They decide whether the endpoint answers "nothing matched" or lists a
/// whole company, which is why they are tested apart from the service.
/// </summary>
public sealed class SupplierCodesTests
{
    [Fact]
    public void SplitTrimsDropsEmptiesAndDeduplicatesWhilePreservingOrder()
    {
        var codes = SupplierCodes.Split(" S2 , S1,, S2 ,S3");

        codes.ShouldBe(["S2", "S1", "S3"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(",")]
    [InlineData(" , , ")]
    public void SplitOfNothingIsEmptyRatherThanAListContainingBlanks(string? raw) =>
        SupplierCodes.Split(raw).ShouldBeEmpty();

    [Fact]
    public void NormalizeIsCaseSensitive()
    {
        // Tenant codes are compared verbatim everywhere else in the service - the database does not
        // fold them either - so two spellings are two suppliers, not one.
        SupplierCodes.Normalize(["s1", "S1"]).ShouldBe(["s1", "S1"]);
    }
}
