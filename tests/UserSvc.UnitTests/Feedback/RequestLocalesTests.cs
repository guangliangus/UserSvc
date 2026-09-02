using Shouldly;
using UserSvc.Application.Features.Feedback;
using Xunit;

namespace UserSvc.UnitTests.Feedback;

/// <summary>
/// The label lookup is an exact, case-sensitive match against jsonb keys, so everything here is
/// really one assertion: whatever a client sends, what reaches that lookup is a key that exists.
/// </summary>
public sealed class RequestLocalesTests
{
    [Theory]
    [InlineData("en", "en")]
    [InlineData("EN", "en")]
    [InlineData("en-US", "en")]
    [InlineData("ja", "ja")]
    [InlineData("ja-JP", "ja")]
    [InlineData("ko-KR", "ko")]
    [InlineData("th", "th")]
    [InlineData("vi-VN", "vi")]
    public void ASupportedLanguageResolvesToItsCanonicalSpelling(string raw, string expected) =>
        RequestLocales.Normalize(raw).ShouldBe(expected);

    [Theory]
    [InlineData("zh-CN", "zh-CN")]
    [InlineData("zh-cn", "zh-CN")]
    [InlineData("zh_CN", "zh-CN")]
    [InlineData("zh", "zh-CN")]
    [InlineData("zh-Hans-CN", "zh-CN")]
    public void SimplifiedChineseVariantsAllLandOnTheSimplifiedKey(string raw, string expected) =>
        RequestLocales.Normalize(raw).ShouldBe(expected);

    [Theory]
    [InlineData("zh-TW")]
    [InlineData("zh-tw")]
    [InlineData("zh-HK")]
    [InlineData("zh-Hant")]
    [InlineData("zh-Hant-TW")]
    public void TraditionalVariantsAreTestedBeforeBareChinese(string raw) =>
        // If the table were ordered the other way round, every one of these would match the bare
        // language subtag first and a Taiwanese phone would be served the Simplified label.
        RequestLocales.Normalize(raw).ShouldBe("zh-TW");

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("de-DE")]
    [InlineData("klingon")]
    public void AnythingElseFallsBackToEnglish(string? raw) =>
        RequestLocales.Normalize(raw).ShouldBe(RequestLocales.Default);

    [Theory]
    [InlineData("engineering")]
    [InlineData("this")]
    [InlineData("viable")]
    public void APrefixMatchNeedsAWholeSubtagNotJustLeadingLetters(string raw) =>
        // Without the trailing hyphen in the comparison, "engineering" would be English and "this"
        // would be Thai.
        RequestLocales.Normalize(raw).ShouldBe(RequestLocales.Default);
}
