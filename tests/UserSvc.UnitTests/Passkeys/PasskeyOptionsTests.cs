using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Ports.Auth;
using UserSvc.Infrastructure.Auth;
using Xunit;

namespace UserSvc.UnitTests.Passkeys;

/// <summary>
/// The relying-party configuration, and the one piece of real logic in it: the Android origin
/// expansion.
/// <para>
/// <b>That expansion is not cosmetic and its absence is not a small bug.</b> A user whose Android
/// credential provider spells the APK signing hash in standard base64 - Xiaomi's HyperOS and
/// several other OEM providers do - fails the origin check at the very last step of every ceremony,
/// with a log line naming an origin that looks identical to the configured one. Both spellings are
/// therefore accepted, and because the origin lives inside signed bytes the acceptance set is
/// widened on the configuration side rather than by rewriting anything the signature covers.
/// </para>
/// </summary>
public sealed class PasskeyOptionsTests
{
    private const string ApkPrefix = "android:apk-key-hash:";

    [Fact]
    public void AnAndroidOriginIsAcceptedInBothBase64Spellings()
    {
        // As Google Play Services sends it: unpadded base64url.
        var options = new PasskeyOptions
        {
            RpId = "liontrip.com",
            RpDisplayName = "LionTrip",
            Origins = [ApkPrefix + "abc-def_ghi"],
        };

        var origins = options.BuildOriginSet();

        origins.ShouldContain(ApkPrefix + "abc-def_ghi");
        origins.ShouldContain(ApkPrefix + "abc+def/ghi", "OEM credential providers send standard base64");
        origins.ShouldContain(ApkPrefix + "abc-def_ghi=", "with padding, which some also send");
        origins.ShouldContain(ApkPrefix + "abc+def/ghi=");
    }

    [Fact]
    public void ConfiguringTheStandardSpellingAlsoAcceptsTheCanonicalOne()
    {
        var options = new PasskeyOptions
        {
            RpId = "liontrip.com",
            RpDisplayName = "LionTrip",
            Origins = [ApkPrefix + "abc+def/ghi="],
        };

        options.BuildOriginSet().ShouldContain(ApkPrefix + "abc-def_ghi");
    }

    [Fact]
    public void AWebOriginIsPassedThroughUntouched()
    {
        var options = new PasskeyOptions
        {
            RpId = "liontrip.com",
            RpDisplayName = "LionTrip",
            Origins = ["  https://liontrip.com  "],
        };

        // Trimmed - the Go service was bugged by an untrimmed comma-separated environment
        // variable - and otherwise left exactly as configured.
        options.BuildOriginSet().ShouldBe(["https://liontrip.com"]);
    }

    [Fact]
    public void AnRpIdWrittenAsAUrlIsRefusedAtStartup()
    {
        var options = new PasskeyOptions
        {
            RpId = "https://liontrip.com",
            RpDisplayName = "LionTrip",
            Origins = ["https://liontrip.com"],
        };

        // Booting with this would produce credentials no authenticator will ever offer back,
        // and nothing at run time would say why.
        Validate(options).ShouldNotBeEmpty();
    }

    [Fact]
    public void AnOriginThatIsNotAUriIsRefusedAtStartup()
    {
        var options = new PasskeyOptions
        {
            RpId = "liontrip.com",
            RpDisplayName = "LionTrip",
            Origins = ["liontrip.com"],
        };

        Validate(options).ShouldNotBeEmpty();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ABlankOriginEntryIsRefusedAtStartupRatherThanSkipped(string blank)
    {
        // The failure this prevents: BuildOriginSet drops blanks, so a list of nothing but blanks
        // validates and then accepts no origin at all. Every ceremony fails at its very last step
        // on a deployment whose configuration looks present - and PASSKEY_RP_ORIGINS set to an
        // empty environment variable produces exactly this list.
        var options = new PasskeyOptions
        {
            RpId = "liontrip.com",
            RpDisplayName = "LionTrip",
            Origins = [blank],
        };

        options.BuildOriginSet().ShouldBeEmpty();
        Validate(options).ShouldNotBeEmpty("an origin list that accepts nothing must not validate");
    }

    [Fact]
    public void ABlankEntryBesideAGoodOneIsStillRefused()
    {
        var options = new PasskeyOptions
        {
            RpId = "liontrip.com",
            RpDisplayName = "LionTrip",
            Origins = ["https://liontrip.com", ""],
        };

        Validate(options).ShouldNotBeEmpty();
    }

    [Fact]
    public void AWorkableConfigurationValidatesAndBuildsACeremony()
    {
        var options = new PasskeyOptions
        {
            RpId = "liontrip.com",
            RpDisplayName = "LionTrip",
            Origins = ["https://liontrip.com", ApkPrefix + "abc-def_ghi"],
        };

        Validate(options).ShouldBeEmpty();

        // Constructing the ceremony is where a bad origin would throw out of Uri, so the assertion
        // that startup validation is enough is that this does not throw.
        IWebAuthnCeremony ceremony = new Fido2WebAuthnCeremony(
            new InMemoryPasskeyFlowStore(),
            Options.Create(options),
            NullLogger<Fido2WebAuthnCeremony>.Instance);

        ceremony.ShouldNotBeNull();
    }

    private static List<ValidationResult> Validate(PasskeyOptions options)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(options, new ValidationContext(options), results, validateAllProperties: true);

        return results;
    }
}
