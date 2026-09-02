using Shouldly;
using UserSvc.Application.Features.Feedback;
using Xunit;

namespace UserSvc.UnitTests.Feedback;

/// <summary>
/// The detector is a closed allow-list, and these tests are as much about what it refuses as what
/// it accepts. A general-purpose sniffer would happily recognise HTML and SVG, and both are
/// executable when a browser opens the URL we hand back.
/// </summary>
public sealed class FeedbackImageRulesTests
{
    [Theory]
    [InlineData("image/jpeg")]
    [InlineData("image/png")]
    [InlineData("image/webp")]
    [InlineData("image/heic")]
    [InlineData("image/heif")]
    public void EveryAcceptedFormatIsDetectedFromItsMagicBytes(string expected)
    {
        var bytes = expected switch
        {
            "image/jpeg" => ImageMagic.Jpeg,
            "image/png" => ImageMagic.Png,
            "image/webp" => ImageMagic.Webp,
            "image/heic" => ImageMagic.Heic,
            _ => ImageMagic.Heif,
        };

        FeedbackImageRules.Detect(bytes).ShouldBe(expected);
        FeedbackImageRules.ExtensionFor(expected).ShouldNotBeEmpty();
    }

    [Fact]
    public void TextIsNotAnImage() => FeedbackImageRules.Detect(ImageMagic.PlainText).ShouldBeEmpty();

    [Fact]
    public void SvgIsRefusedEvenThoughItIsAnImageFormat()
    {
        // It is an image to a human and a script host to a browser. Accepting it would turn the
        // feedback container into somewhere an attacker can host active content on our domain.
        FeedbackImageRules.Detect("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"u8).ShouldBeEmpty();
    }

    [Fact]
    public void HtmlIsRefused() =>
        FeedbackImageRules.Detect("<!DOCTYPE html><html><body>hi</body></html>"u8).ShouldBeEmpty();

    [Fact]
    public void GifIsRefusedBecauseItIsNotOnTheList() =>
        FeedbackImageRules.Detect("GIF89a  "u8).ShouldBeEmpty();

    [Fact]
    public void ARiffContainerThatIsNotWebpIsRefused()
    {
        // A WAV file starts with the same four bytes. Checking only the RIFF marker would accept it.
        byte[] wav = [.. "RIFF"u8, 0x00, 0x00, 0x00, 0x00, .. "WAVEfmt "u8];

        FeedbackImageRules.Detect(wav).ShouldBeEmpty();
    }

    [Fact]
    public void AnIsoContainerWithAnUnknownBrandIsRefused()
    {
        // ftyp with the mp42 brand is a video file, not a still image.
        byte[] mp4 = [0x00, 0x00, 0x00, 0x18, .. "ftypmp42"u8, .. "mp42isom"u8];

        FeedbackImageRules.Detect(mp4).ShouldBeEmpty();
    }

    [Fact]
    public void ATruncatedHeaderIsRefusedRatherThanCrashing()
    {
        // Everything here indexes into the span; a file shorter than the signature must fall
        // through the length guards rather than throw.
        FeedbackImageRules.Detect([0xFF, 0xD8]).ShouldBeEmpty();
        FeedbackImageRules.Detect([]).ShouldBeEmpty();
        FeedbackImageRules.Detect("RIFF"u8).ShouldBeEmpty();
    }

    [Fact]
    public void TheRefusalMessageNamesTheFormatsSoTheCallerKnowsWhatToConvertTo()
    {
        FeedbackImageRules.UnsupportedTypeMessage.ShouldContain("image/jpeg");
        FeedbackImageRules.UnsupportedTypeMessage.ShouldContain("image/heic");
    }

    [Fact]
    public void NoAttachmentsIsAnEmptyListRatherThanAFailure()
    {
        FeedbackImageRules.Validate(null).ShouldBeEmpty();
        FeedbackImageRules.Validate([]).ShouldBeEmpty();
    }
}
