using Shouldly;
using UserSvc.Application.Features.BackOffice.TestWhitelist;
using Xunit;

namespace UserSvc.UnitTests.TestWhitelist;

/// <summary>
/// The paging arithmetic. Small, and worth its own tests: two of these cases are the ones that turn
/// a query with a perfectly good answer into a 500.
/// </summary>
public sealed class TestWhitelistPagingTests
{
    [Theory]
    [InlineData(0, 0, 1, TestWhitelistPaging.DefaultPageSize)]
    [InlineData(-5, -1, 1, TestWhitelistPaging.DefaultPageSize)]
    [InlineData(3, 500, 3, TestWhitelistPaging.MaxPageSize)]
    [InlineData(2, 50, 2, 50)]
    public void OutOfRangePagingIsCorrectedRatherThanRefused(
        int page, int pageSize, int expectedPage, int expectedPageSize) =>
        TestWhitelistPaging.Normalize(page, pageSize).ShouldBe((expectedPage, expectedPageSize));

    [Fact]
    public void SliceReturnsTheRequestedWindow() =>
        TestWhitelistPaging.Slice([1, 2, 3, 4, 5], 2, 2).ShouldBe([3, 4]);

    [Fact]
    public void ASliceThatRunsPastTheEndIsTruncatedRatherThanRefused() =>
        TestWhitelistPaging.Slice([1, 2, 3], 2, 2).ShouldBe([3]);

    [Fact]
    public void APageBeyondTheEndIsEmpty()
    {
        // A listing whose last member was just removed should render as empty, not fail.
        TestWhitelistPaging.Slice([1, 2, 3], 9, 20).ShouldBeEmpty();
    }

    [Fact]
    public void TheLargestPageNumberAnIntCanHoldDoesNotOverflowIntoAnException()
    {
        // (page - 1) * pageSize in int arithmetic wraps negative here, and Skip refuses a negative
        // count - a 500 for a query whose correct answer is an empty page.
        TestWhitelistPaging.Slice([1, 2, 3], int.MaxValue, TestWhitelistPaging.MaxPageSize)
            .ShouldBeEmpty();
    }

    [Theory]
    [InlineData(0, 20, 0)]
    [InlineData(1, 20, 1)]
    [InlineData(20, 20, 1)]
    [InlineData(21, 20, 2)]
    [InlineData(5, 0, 0)]
    public void TotalPagesCeilingDivides(int total, int pageSize, int expected) =>
        TestWhitelistPaging.TotalPages(total, pageSize).ShouldBe(expected);
}
