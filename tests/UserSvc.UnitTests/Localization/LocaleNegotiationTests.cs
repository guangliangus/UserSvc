using Shouldly;
using UserSvc.Application.Features.Localization;
using Xunit;

namespace UserSvc.UnitTests.Localization;

/// <summary>
/// The precedence between the two headers that can name a language, and the requested-versus-
/// defaulted distinction that decides whether an error <c>detail</c> is translated at all.
/// <para>
/// This is pinned here rather than in the middleware because the rule is the decision, and the
/// middleware around it does nothing but read two strings off the request. It was previously
/// reachable only through the API project, which the unit tests deliberately do not reference -
/// so the one rule most likely to be "improved" by a later reader had no test at all.
/// </para>
/// </summary>
public sealed class LocaleNegotiationTests
{
    /// <summary>
    /// <c>X-Language</c> is a client stating its own UI language; <c>Accept-Language</c> is the
    /// operating system's guess. When both are present the explicit one wins, and getting this
    /// backwards would answer a Japanese app in whatever language the phone happens to be set to.
    /// </summary>
    [Fact]
    public void TheExplicitHeaderBeatsTheBrowsersGuess()
    {
        var negotiated = LocaleNegotiation.Resolve("ja", "th,en;q=0.5");

        negotiated.Locale.ShouldBe("ja");
        negotiated.Source.ShouldBe(LocaleSource.LanguageHeader);
        negotiated.WasRequested.ShouldBeTrue();
    }

    /// <summary>
    /// An <c>X-Language</c> this service has no text for falls through to <c>Accept-Language</c>
    /// rather than to English: a Danish app whose browser asks for Thai is better served in Thai
    /// than defaulted into English by a header that named a language we simply do not have.
    /// </summary>
    [Fact]
    public void AnUnsupportedExplicitHeaderFallsThroughRatherThanToEnglish()
    {
        var negotiated = LocaleNegotiation.Resolve("da-DK", "th");

        negotiated.Locale.ShouldBe("th");
        negotiated.Source.ShouldBe(LocaleSource.AcceptLanguage);
        negotiated.WasRequested.ShouldBeTrue();
    }

    [Fact]
    public void TheBrowsersHeaderAnswersWhenItIsTheOnlyOne()
    {
        var negotiated = LocaleNegotiation.Resolve(null, "zh-TW,zh;q=0.9");

        negotiated.Locale.ShouldBe("zh-TW");
        negotiated.Source.ShouldBe(LocaleSource.AcceptLanguage);
    }

    /// <summary>
    /// The load-bearing negative case. A caller that asked for nothing must come back
    /// <b>not requested</b>, because that is the flag the ProblemDetails seam reads: false means
    /// the response keeps the exact sentence its throw site wrote. Flip this and every existing
    /// response in the service is silently reworded.
    /// </summary>
    [Theory]
    [InlineData(null, null)]
    [InlineData("", "")]
    [InlineData("   ", "   ")]
    [InlineData("da-DK", "de-DE,fr;q=0.8")]
    [InlineData(null, "*")]
    public void ACallerThatAskedForNothingIsNotTreatedAsHavingAskedForEnglish(
        string? language, string? acceptLanguage)
    {
        var negotiated = LocaleNegotiation.Resolve(language, acceptLanguage);

        negotiated.Locale.ShouldBe(SupportedLocales.Default);
        negotiated.WasRequested.ShouldBeFalse();
        negotiated.Source.ShouldBe(LocaleSource.Default);
    }

    /// <summary>
    /// Asking for English is not the same as asking for nothing, even though both answer
    /// <c>en</c>. The Go normalizer's own comment insisted on keeping the two apart; here the
    /// difference is whether the catalogue's English sentence replaces the throw site's.
    /// </summary>
    [Fact]
    public void AskingForEnglishIsDistinguishableFromNotAsking()
    {
        LocaleNegotiation.Resolve("en", null).WasRequested.ShouldBeTrue();
        LocaleNegotiation.Resolve(null, null).WasRequested.ShouldBeFalse();
    }

    [Fact]
    public void TheDefaultIsEnglishAndNotRequested()
    {
        NegotiatedLocale.Default.Locale.ShouldBe("en");
        NegotiatedLocale.Default.WasRequested.ShouldBeFalse();
    }
}
