using Shouldly;
using UserSvc.Application.Features.Localization;
using Xunit;

namespace UserSvc.UnitTests.Localization;

/// <summary>
/// The normalizer is the front door of every localized answer, so what is pinned here is really one
/// property: whatever a client sends, what comes out is one of seven codes that a bundle and a jsonb
/// label map both actually have a key for.
/// </summary>
public sealed class SupportedLocalesTests
{
    [Theory]
    [InlineData("en", "en")]
    [InlineData("EN", "en")]
    [InlineData("  en-US  ", "en")]
    [InlineData("ja", "ja")]
    [InlineData("ja-JP", "ja")]
    [InlineData("ko-KR", "ko")]
    [InlineData("th", "th")]
    [InlineData("vi-VN", "vi")]
    public void ASupportedLanguageResolvesToItsCanonicalSpelling(string raw, string expected) =>
        SupportedLocales.Normalize(raw).ShouldBe(expected);

    /// <summary>
    /// The deliberate quirk, and the one that has already caused a bug: <b>bare <c>zh</c> means
    /// Simplified</b>. The language subtag alone does not say which script, and this table resolves
    /// the ambiguity rather than refusing - so anything Chinese-ish that is not on the Traditional
    /// list lands here too.
    /// </summary>
    [Theory]
    [InlineData("zh")]
    [InlineData("zh-CN")]
    [InlineData("zh-cn")]
    [InlineData("zh_CN")]
    [InlineData("zh-Hans")]
    [InlineData("zh-Hans-CN")]
    [InlineData("zh-SG")]
    public void BareChineseAndSimplifiedVariantsLandOnSimplified(string raw) =>
        SupportedLocales.Normalize(raw).ShouldBe(SupportedLocales.SimplifiedChinese);

    /// <summary>
    /// Order is load-bearing. If the Simplified entry's bare <c>zh</c> prefix were tested first,
    /// every one of these would match it and a Taiwanese phone would be served Simplified Chinese -
    /// invisible in English testing, reported months later as "the app is in the wrong language".
    /// </summary>
    [Theory]
    [InlineData("zh-TW")]
    [InlineData("zh-tw")]
    [InlineData("zh-HK")]
    [InlineData("zh-MO")]
    [InlineData("zh-Hant")]
    [InlineData("zh-Hant-TW")]
    public void TraditionalVariantsAreTestedBeforeBareChinese(string raw) =>
        SupportedLocales.Normalize(raw).ShouldBe(SupportedLocales.TraditionalChinese);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("de-DE")]
    [InlineData("klingon")]
    public void AnythingElseFallsBackToEnglish(string? raw) =>
        SupportedLocales.Normalize(raw).ShouldBe(SupportedLocales.Default);

    /// <summary>
    /// A prefix must be a whole subtag. Without the trailing hyphen in the comparison
    /// "engineering" would be English, "this" would be Thai and "viable" would be Vietnamese - and
    /// each of those is a plausible thing to find in a mis-set header.
    /// </summary>
    [Theory]
    [InlineData("engineering")]
    [InlineData("this")]
    [InlineData("viable")]
    [InlineData("zhtw")]
    public void APrefixMatchNeedsAWholeSubtagNotJustLeadingLetters(string raw) =>
        SupportedLocales.Normalize(raw).ShouldBe(SupportedLocales.Default);

    /// <summary>
    /// The distinction the Go comment insisted on keeping: "real English" is not the same answer as
    /// "defaulted to English". Error-detail translation keys off it, so collapsing the two would
    /// silently start rewriting the detail of every response in the service.
    /// </summary>
    [Fact]
    public void AskingForEnglishIsDistinguishableFromAskingForNothing()
    {
        SupportedLocales.TryNormalize("en-GB", out var asked).ShouldBeTrue();
        asked.ShouldBe("en");

        SupportedLocales.TryNormalize("  ", out var defaulted).ShouldBeFalse();
        defaulted.ShouldBe(SupportedLocales.Default);

        SupportedLocales.TryNormalize("de-DE", out var unknown).ShouldBeFalse();
        unknown.ShouldBe(SupportedLocales.Default);
    }

    [Fact]
    public void TheTableIsTheSevenLocalesTheBundlesAndTheMenuSeedShare() =>
        SupportedLocales.Codes.ShouldBe(["en", "ja", "zh-TW", "zh-CN", "ko", "th", "vi"]);

    /// <summary>
    /// <see cref="UserSvc.Application.Features.Feedback.RequestLocales"/> is the same table, written
    /// first for the feedback labels and left in place here because moving it would touch another
    /// slice's files. Two copies of a locale table drift, and the symptom is one endpoint answering
    /// in a different language from the next - so until it is deleted, this test is what keeps them
    /// honest.
    /// </summary>
    [Theory]
    [InlineData("en")]
    [InlineData("EN")]
    [InlineData("en-US")]
    [InlineData("ja-JP")]
    [InlineData("ko-KR")]
    [InlineData("th")]
    [InlineData("vi-VN")]
    [InlineData("zh")]
    [InlineData("zh_CN")]
    [InlineData("zh-Hans-CN")]
    [InlineData("zh-TW")]
    [InlineData("zh-HK")]
    [InlineData("zh-MO")]
    [InlineData("zh-Hant-TW")]
    [InlineData("de-DE")]
    [InlineData("engineering")]
    [InlineData("")]
    public void ItAgreesWithTheFeedbackTableItSupersedes(string raw) =>
        SupportedLocales.Normalize(raw)
            .ShouldBe(UserSvc.Application.Features.Feedback.RequestLocales.Normalize(raw));
}
