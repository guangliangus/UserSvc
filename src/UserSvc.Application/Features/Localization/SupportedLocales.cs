namespace UserSvc.Application.Features.Localization;

/// <summary>
/// One language this service can answer in: the canonical spelling that leaves the service, the
/// loose tags a client may send for it, and the short label a picker renders.
/// <para>
/// The Go table also carried each language's name written in that language. It is not ported:
/// nothing in this service renders a language picker, and a non-ASCII literal in a <c>.cs</c> file
/// fails this repository's source-language guard. When a picker endpoint appears, that name belongs
/// in the locale bundle which describes it, not in this table.
/// </para>
/// </summary>
public sealed record LocaleSpec(string Code, IReadOnlyList<string> Prefixes, string Short);

/// <summary>
/// The closed set of seven locales, and the normalizer that maps loose client input onto it.
/// <para>
/// This is the single source of truth for language metadata: adding a language is one entry here
/// plus one JSON bundle beside <see cref="ErrorMessageCatalog"/> — no other code changes, and the
/// catalogue coverage test starts demanding translations for it immediately.
/// </para>
/// <para>
/// <b>The order of the table is load-bearing and it encodes a deliberate quirk.</b> Matching is
/// exact-or-dash-prefix, so every Traditional Chinese tag must be tested before the bare
/// <c>zh</c> prefix that belongs to Simplified. Get the order wrong and <c>zh-TW</c> matches
/// <c>zh</c> first, and a Taiwanese client is served Simplified Chinese — a bug that is invisible
/// in English testing and reaches the service desk as "the app is in the wrong language".
/// <b>Bare <c>zh</c> means Simplified</b>, which is the quirk itself: the language subtag alone
/// does not say which script, and this table resolves the ambiguity towards <c>zh-CN</c> rather
/// than refusing. Anything else Chinese-ish and unlisted (<c>zh-SG</c>, <c>zh-Hans</c>) therefore
/// also lands on Simplified.
/// </para>
/// </summary>
public static class SupportedLocales
{
    /// <summary>The locale everything falls back to, and the one key every bundle carries.</summary>
    public const string Default = "en";

    public const string English = "en";
    public const string Japanese = "ja";
    public const string TraditionalChinese = "zh-TW";
    public const string SimplifiedChinese = "zh-CN";
    public const string Korean = "ko";
    public const string Thai = "th";
    public const string Vietnamese = "vi";

    /// <summary>
    /// In the order matching must iterate. See the type remarks: the Traditional entry precedes the
    /// bare <c>zh</c> on the Simplified one, and swapping them is a user-visible bug.
    /// </summary>
    public static readonly IReadOnlyList<LocaleSpec> All =
    [
        new(English, ["en"], "EN"),
        new(Japanese, ["ja"], "JA"),

        // zh-mo (Macau) is not in the Go table; it is Traditional in practice and was already
        // matched here by the feedback normalizer this type consolidates. Keeping it is a superset,
        // never a reinterpretation of a tag Go handled differently.
        new(TraditionalChinese, ["zh-tw", "zh-hk", "zh-mo", "zh-hant"], "ZH-TW"),
        new(SimplifiedChinese, ["zh"], "ZH-CN"),
        new(Korean, ["ko"], "KO"),
        new(Thai, ["th"], "TH"),
        new(Vietnamese, ["vi"], "VI"),
    ];

    /// <summary>The canonical codes, in table order.</summary>
    public static readonly IReadOnlyList<string> Codes = [.. All.Select(spec => spec.Code)];

    /// <summary>
    /// The canonical locale for a raw tag, or <see cref="Default"/> when it is missing, blank or
    /// names a language this service has no text for.
    /// <para>
    /// A caller that needs to tell "the client asked for English" apart from "the client asked for
    /// nothing we know" must use <see cref="TryNormalize"/> — this overload collapses both onto
    /// <c>en</c>, exactly as the Go <c>DataLocaleOf</c> did.
    /// </para>
    /// </summary>
    public static string Normalize(string? raw) =>
        TryNormalize(raw, out var locale) ? locale : Default;

    /// <summary>
    /// The canonical locale for a raw tag, and whether it actually matched.
    /// <para>
    /// The distinction is the Go comment's, kept because it is load-bearing here: <i>"preserve the
    /// caller-supplied default so callers can distinguish real English from default-to-English
    /// fallback"</i>. Translation of error <c>detail</c> keys off it — a client that asked for a
    /// language gets the catalogue's sentence, a client that asked for nothing keeps the sentence
    /// its throw site wrote.
    /// </para>
    /// </summary>
    public static bool TryNormalize(string? raw, out string locale)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            locale = Default;
            return false;
        }

        // Underscores fold to hyphens because Android and several older clients send zh_CN rather
        // than zh-CN, and BCP 47 has no underscore to be faithful to.
        var candidate = raw.Trim().ToLowerInvariant().Replace('_', '-');

        foreach (var spec in All)
        {
            foreach (var prefix in spec.Prefixes)
            {
                // Either the tag itself or a subtag of it. The trailing hyphen is what makes this a
                // subtag match rather than a substring one: without it "engineering" would be
                // English, "this" would be Thai and "viable" would be Vietnamese.
                if (candidate.Equals(prefix, StringComparison.Ordinal)
                    || candidate.StartsWith(prefix + "-", StringComparison.Ordinal))
                {
                    locale = spec.Code;
                    return true;
                }
            }
        }

        locale = Default;
        return false;
    }
}
