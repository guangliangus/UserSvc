using Shouldly;
using UserSvc.Application.Features.Localization;
using Xunit;

namespace UserSvc.UnitTests.Localization;

/// <summary>
/// <c>Accept-Language</c> is the addition this service makes to the Go contract, so everything it
/// does is pinned here rather than inferred from the RFC.
/// </summary>
public sealed class AcceptLanguageNegotiatorTests
{
    [Theory]
    [InlineData("ja", "ja")]
    [InlineData("ja-JP", "ja")]
    [InlineData("zh-TW,zh;q=0.9", "zh-TW")]
    [InlineData("en-US,en;q=0.9", "en")]
    public void ThePreferredSupportedLanguageWins(string header, string expected) =>
        AcceptLanguageNegotiator.Negotiate(header).ShouldBe(expected);

    /// <summary>Quality decides, not document order.</summary>
    [Fact]
    public void AHigherQualityLaterInTheListStillWins() =>
        AcceptLanguageNegotiator.Negotiate("en;q=0.5,ja;q=0.9").ShouldBe("ja");

    /// <summary>Equal quality keeps the order the client wrote, which is what the RFC intends.</summary>
    [Fact]
    public void EqualQualitiesFallBackToTheClientsOwnOrder() =>
        AcceptLanguageNegotiator.Negotiate("ja,ko").ShouldBe("ja");

    /// <summary>Languages this service has no text for are skipped, not defaulted to.</summary>
    [Fact]
    public void UnsupportedLanguagesAreSkippedInFavourOfSupportedOnes() =>
        AcceptLanguageNegotiator.Negotiate("de,fr,th;q=0.1").ShouldBe("th");

    /// <summary><c>q=0</c> is an explicit refusal of that language, not a low ranking of it.</summary>
    [Fact]
    public void AZeroQualityEntryIsRefusedRatherThanRankedLast() =>
        AcceptLanguageNegotiator.Negotiate("ja;q=0,ko;q=0.2").ShouldBe("ko");

    /// <summary>
    /// The wildcard means "anything", which is not a request for a language. Reading it as one
    /// would let a browser that expressed no preference silently switch a caller's error messages.
    /// </summary>
    [Fact]
    public void TheWildcardIsNotARequestForALanguage() =>
        AcceptLanguageNegotiator.Negotiate("*").ShouldBeNull();

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("de-DE, fr-FR;q=0.8")]
    public void NothingSupportedMeansNoAnswerRatherThanEnglish(string? header) =>
        AcceptLanguageNegotiator.Negotiate(header).ShouldBeNull();

    /// <summary>
    /// A malformed weight defaults the entry to 1 rather than dropping it: a client bug should not
    /// be answered by silently switching the user's language.
    /// </summary>
    [Fact]
    public void AnUnparseableQualityStillCountsAsAPreference() =>
        AcceptLanguageNegotiator.Negotiate("ko;q=high").ShouldBe("ko");
}
