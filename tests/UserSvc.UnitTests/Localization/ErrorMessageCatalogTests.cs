using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Localization;
using Xunit;

namespace UserSvc.UnitTests.Localization;

/// <summary>
/// The catalogue degrades rather than throwing, which moves the completeness guarantee out of
/// startup and into here. These tests are therefore the enforcement, not a description of it: a
/// bundle that fails to load or a code that is missing a language fails the build.
/// </summary>
public sealed class ErrorMessageCatalogTests
{
    /// <summary>The 112 codes the ported bundles carry, whichever bundle they came from.</summary>
    private const int PortedCodeCount = 112;

    /// <summary>
    /// Codes added to the bundles here rather than ported: <c>CONCURRENCY_CONFLICT</c>,
    /// <c>NOT_IMPLEMENTED</c> and <c>CONFLICT</c>, none of which Go had a message for, plus
    /// <c>LAST_LOGIN_METHOD</c>, which exists so that <c>CONFLICT</c> could have one. Counted
    /// separately so the ported figure above stays a statement about the port.
    /// </summary>
    private const int AddedCodeCount = 4;

    /// <summary>
    /// The B2B tenant and RBAC vocabulary every operator-facing refusal draws on. A code that falls
    /// back to itself is an untranslated code, not a translation - and these are the ones an
    /// external administrator reads most often, in a language they did not choose.
    /// </summary>
    private static readonly string[] B2BCodes =
    [
        "TENANT_CONTEXT_REQUIRED", "NO_TENANT_BOUND", "TENANT_NOT_AUTHORIZED", "TENANT_DISABLED",
        "MENU_NOT_GRANTED", "ROLE_NOT_AVAILABLE", "ROLE_CODE_RESERVED", "ROLE_NOT_DELEGABLE",
        "ROLE_IN_USE", "ADMIN_TRANSFER_REQUIRED", "ADMIN_ROLE_REQUIRED", "MEMBER_NOT_FOUND",
        "MEMBER_ALREADY_EXISTS", "SUPPLIER_NOT_APPROVED", "SUPPLIER_ALREADY_LINKED",
        "COMPANY_NOT_FOUND", "SUPPLIER_NOT_FOUND", "CALLER_NOT_ADMIN", "SUPER_ADMIN_REQUIRED",
        "ROLE_OWNER_REQUIRED", "ROLE_OWNER_NOT_ALLOWED", "ROLE_PARENT_INVALID", "ROLE_HAS_CHILDREN",
        "ROLE_GRANTS_EXCEED_PARENT", "MENU_HAS_CHILDREN", "ROLE_CATEGORY_INVALID",
        "ROLE_CATEGORY_MISMATCH", "ROLE_NOT_GLOBAL_ASSIGNABLE",
    ];

    /// <summary>
    /// The codes the generic response paths reach for. They are worth naming separately because
    /// they are not thrown from one feature - they are what a 400, a 401, a 403, a 404, a 429 and a
    /// 500 come out as, which makes them the codes a caller is most likely to ever see.
    /// </summary>
    private static readonly string[] GeneralCodes =
    [
        ErrorCodes.BadRequest, ErrorCodes.ValidationFailed, ErrorCodes.Unauthorized,
        ErrorCodes.Forbidden, ErrorCodes.NotFound, ErrorCodes.RateLimitExceeded,
        ErrorCodes.UpstreamUnavailable, ErrorCodes.InternalError, ErrorCodes.MissingHeader,
        ErrorCodes.TenantContextRequired, ErrorCodes.InvalidToken, ErrorCodes.ExpiredToken,
        ErrorCodes.SessionRevoked, ErrorCodes.ConcurrencyConflict, ErrorCodes.NotImplemented,
        ErrorCodes.Conflict,
    ];

    /// <summary>Every bundle is an embedded resource compiled into the assembly, so the only way to
    /// produce a failure is a packaging mistake - which is exactly what this catches.</summary>
    [Fact]
    public void EveryBundleLoads() =>
        ErrorMessageCatalog.LoadFailures.ShouldBeEmpty();

    [Fact]
    public void TheWholePortedCatalogueIsPresent() =>
        ErrorMessageCatalog.All.Count.ShouldBe(PortedCodeCount + AddedCodeCount);

    /// <summary>
    /// Adding a language to <see cref="SupportedLocales.All"/> automatically expands the requirement
    /// here: every code any bundle carries must be present and non-empty in every locale. That is
    /// the point - a half-translated language is worse than an absent one, because it looks like it
    /// works until a user hits the gap.
    /// </summary>
    [Fact]
    public void EveryCodeIsTranslatedInEverySupportedLocale()
    {
        var gaps = new List<string>();

        foreach (var (code, byLocale) in ErrorMessageCatalog.All)
        {
            foreach (var locale in SupportedLocales.Codes)
            {
                if (!byLocale.TryGetValue(locale, out var message) || message.Length == 0)
                {
                    gaps.Add($"{locale}: {code}");
                }
            }
        }

        gaps.ShouldBeEmpty();
    }

    [Fact]
    public void TheB2BTenantAndRbacCodesAreTranslatedEverywhere() =>
        AssertTranslatedEverywhere(B2BCodes);

    [Fact]
    public void TheGeneralResponseCodesAreTranslatedEverywhere() =>
        AssertTranslatedEverywhere(GeneralCodes);

    /// <summary>
    /// Every alias points at a code the bundles actually carry. An alias whose target is missing is
    /// worse than no alias: the code silently stops translating and looks like a gap in the
    /// bundles rather than a typo in one line of C#.
    /// </summary>
    [Fact]
    public void EveryAliasResolvesToARealEntry()
    {
        foreach (var (code, target) in ErrorMessageCatalog.AliasedCodes)
        {
            ErrorMessageCatalog.All.ShouldContainKey(
                target, $"alias {code} -> {target} points at nothing.");
        }
    }

    /// <summary>
    /// The spelling divergence that made the alias table necessary in the first place:
    /// <see cref="ErrorCodes"/> is add-only, so the published constant keeps its extra syllable
    /// while the ported bundle keeps Go's.
    /// </summary>
    [Fact]
    public void TheDotNetSpellingOfTheGlobalAssignableCodeStillTranslates()
    {
        ErrorMessageCatalog.All.ShouldNotContainKey(ErrorCodes.RoleNotGloballyAssignable);

        ErrorMessageCatalog.Translate(ErrorCodes.RoleNotGloballyAssignable, "zh-TW")
            .ShouldBe(ErrorMessageCatalog.Translate("ROLE_NOT_GLOBAL_ASSIGNABLE", "zh-TW"));
    }

    /// <summary>
    /// <see cref="ErrorCodes.NotConfigured"/> must never gain a translation or an alias. Its detail
    /// carries the names of the configuration sections a deployment is missing, and that is the
    /// entire value of the response - a translated sentence would send the operator to read code
    /// instead of secrets.
    /// </summary>
    [Fact]
    public void AMissingConfigurationIsNeverTranslated()
    {
        ErrorMessageCatalog.Covers(ErrorCodes.NotConfigured).ShouldBeFalse();

        ErrorMessageCatalog.TryTranslate(ErrorCodes.NotConfigured, "ja", out _).ShouldBeFalse();
    }

    /// <summary>
    /// The generic conflict bucket is translatable only because the one refusal in it that had
    /// something else to say was given <see cref="ErrorCodes.LastLoginMethod"/>. Both are pinned
    /// here: if the two ever collapse back into one code, one of these sentences becomes a lie, and
    /// it would be the one telling a user how to avoid locking themselves out.
    /// </summary>
    [Fact]
    public void TheConflictBucketAndTheLockoutRefusalSayDifferentThings()
    {
        var conflict = ErrorMessageCatalog.Translate(ErrorCodes.Conflict, "ja");
        var lockout = ErrorMessageCatalog.Translate(ErrorCodes.LastLoginMethod, "ja");

        conflict.ShouldNotBe(ErrorCodes.Conflict);
        lockout.ShouldNotBe(ErrorCodes.LastLoginMethod);
        conflict.ShouldNotBe(lockout);
    }

    /// <summary>
    /// <see cref="ErrorCodes.LastLoginMethod"/> is the general form of
    /// <c>PASSKEY_LAST_LOGIN_METHOD</c> and deliberately shares its wording - two codes, one
    /// sentence, because it is the same thing happening to a different credential. Pinned so a
    /// later edit to one of them does not silently leave the other saying something else.
    /// </summary>
    [Fact]
    public void TheLockoutRefusalReadsTheSameWhicheverCredentialItIsAbout() =>
        SupportedLocales.Codes.ShouldAllBe(locale =>
            ErrorMessageCatalog.Translate(ErrorCodes.LastLoginMethod, locale)
                == ErrorMessageCatalog.Translate(ErrorCodes.PasskeyLastLoginMethod, locale));

    /// <summary>
    /// The fallback chain, verbatim from the Go contract: locale, then English, then the code.
    /// Echoing the code is why the response seam uses <c>TryTranslate</c> instead - a detail reading
    /// "SOME_UNKNOWN_CODE" is strictly worse than the English sentence it would replace.
    /// </summary>
    [Fact]
    public void AnUnknownCodeEchoesItselfAndAnUnknownLocaleFallsBackToEnglish()
    {
        ErrorMessageCatalog.Translate("SOME_UNKNOWN_CODE", "en").ShouldBe("SOME_UNKNOWN_CODE");

        ErrorMessageCatalog.Translate("NO_TENANT_BOUND", "xx-XX")
            .ShouldBe(ErrorMessageCatalog.Translate("NO_TENANT_BOUND", "en"));
    }

    /// <summary>
    /// The seam's own contract: a code the catalogue does not carry answers false, so the caller
    /// keeps whatever sentence it already had.
    /// </summary>
    [Fact]
    public void TranslationIsDeclinedRatherThanInventedForAnUnknownCode()
    {
        ErrorMessageCatalog.TryTranslate("SOME_UNKNOWN_CODE", "ja", out var message).ShouldBeFalse();
        message.ShouldBeNull();
    }

    /// <summary>Seven locales means seven different sentences, not one repeated.</summary>
    [Fact]
    public void TheSameCodeReadsDifferentlyInEachLanguage() =>
        SupportedLocales.Codes
            .Select(locale => ErrorMessageCatalog.Translate(ErrorCodes.Unauthorized, locale))
            .Distinct(StringComparer.Ordinal)
            .Count()
            .ShouldBe(SupportedLocales.Codes.Count);

    private static void AssertTranslatedEverywhere(string[] codes)
    {
        var gaps = new List<string>();

        foreach (var code in codes)
        {
            foreach (var locale in SupportedLocales.Codes)
            {
                var message = ErrorMessageCatalog.Translate(code, locale);

                if (message.Length == 0 || string.Equals(message, code, StringComparison.Ordinal))
                {
                    gaps.Add($"{locale}: {code}");
                }
            }
        }

        gaps.ShouldBeEmpty();
    }
}
