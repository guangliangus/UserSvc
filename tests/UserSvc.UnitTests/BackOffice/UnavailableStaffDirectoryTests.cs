using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Infrastructure.External;
using Xunit;

namespace UserSvc.UnitTests.BackOffice;

/// <summary>
/// The placeholder's answers are the point of these tests. "It is only a stand-in" is exactly the
/// argument that would let it start verifying one-time passwords, so both refusals are pinned here
/// together with the reason each is the only safe answer.
/// </summary>
public sealed class UnavailableStaffDirectoryTests
{
    private static UnavailableStaffDirectory Sut =>
        new(NullLogger<UnavailableStaffDirectory>.Instance);

    /// <summary>
    /// This method is the entire credential check for staff who have no local password. Answering
    /// "verified" would sign in anyone who typed anything; answering "not verified" would be a
    /// quieter lie - the client would be told its code was wrong and nobody would ever learn that
    /// nothing had been checked.
    /// </summary>
    [Fact]
    public async Task VerifyingAOneTimePasswordRefusesRatherThanAnswering()
    {
        var ex = await Should.ThrowAsync<AppException>(
            () => Sut.VerifyOtpAsync("260022", "2449673", CancellationToken.None));

        // 501, not 502: nothing upstream failed, because nothing upstream was asked.
        ex.StatusCode.ShouldBe(501);
        ex.ErrorCode.ShouldBe(ErrorCodes.NotImplemented);
    }

    /// <summary>
    /// Deliberately not a 404. "No such employee" is an answer this component does not have, and a
    /// 404 would let the caller conclude the employee does not exist when the truth is that nobody
    /// looked.
    /// </summary>
    [Fact]
    public async Task FetchingAStaffProfileRefusesRatherThanAnsweringNotFound()
    {
        var ex = await Should.ThrowAsync<AppException>(
            () => Sut.GetStaffProfileAsync("260022", CancellationToken.None));

        ex.StatusCode.ShouldBe(501);
        ex.ShouldNotBeOfType<NotFoundException>();
    }

    /// <summary>The refusal message names the capability, never the employee number it was asked
    /// about - the message is rendered into the response body verbatim.</summary>
    [Fact]
    public async Task TheRefusalMessageCarriesNoCallerInput()
    {
        var ex = await Should.ThrowAsync<AppException>(
            () => Sut.VerifyOtpAsync("260022", "2449673", CancellationToken.None));

        ex.Message.ShouldNotContain("260022");
        ex.Message.ShouldNotContain("2449673");
    }
}
