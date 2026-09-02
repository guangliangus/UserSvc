namespace UserSvc.Application.Features.Feedback;

/// <summary>
/// Turns whatever a client puts in the language header into one of the seven locales this
/// service's data is actually written in.
/// <para>
/// It exists because the label lookup is an <b>exact, case-sensitive</b> key match against a jsonb
/// object whose keys are spelled <c>zh-CN</c> and <c>zh-TW</c>. Handing that lookup the raw header
/// would mean <c>zh-cn</c>, <c>zh_CN</c> and <c>zh-Hans-CN</c> all silently fall through to English
/// on a Simplified Chinese phone - a bug that is invisible in English testing and reported as
/// "the app is in the wrong language" months later.
/// </para>
/// <para>
/// <b>The order of the table is load-bearing.</b> Every entry is a prefix match, so the Traditional
/// variants must be tested before bare <c>zh</c>; the other way round, a Taiwanese client asking for
/// <c>zh-TW</c> would match <c>zh</c> first and be served Simplified.
/// </para>
/// <para>
/// It lives in the feedback feature because feedback is the first thing that needs it. When a
/// second caller appears it should move up beside the other cross-cutting request helpers rather
/// than being copied - two copies of a locale table drift, and the symptom is one endpoint
/// answering in a different language from the next.
/// </para>
/// </summary>
public static class RequestLocales
{
    /// <summary>The locale everything falls back to, and the one key every seeded label carries.</summary>
    public const string Default = "en";

    /// <summary>Prefixes to canonical locale, in the order they must be tested.</summary>
    private static readonly (string[] Prefixes, string Canonical)[] Table =
    [
        (["en"], "en"),
        (["ja"], "ja"),
        (["zh-tw", "zh-hk", "zh-mo", "zh-hant"], "zh-TW"),
        (["zh"], "zh-CN"),
        (["ko"], "ko"),
        (["th"], "th"),
        (["vi"], "vi"),
    ];

    /// <summary>
    /// The canonical locale for a raw header value; <see cref="Default"/> when it is missing, blank
    /// or names a language this service has no labels for.
    /// </summary>
    public static string Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Default;
        }

        // Underscores are folded to hyphens because Android and several older clients send
        // zh_CN rather than zh-CN, and BCP 47 has no underscore to be faithful to.
        var candidate = raw.Trim().ToLowerInvariant().Replace('_', '-');

        foreach (var (prefixes, canonical) in Table)
        {
            foreach (var prefix in prefixes)
            {
                // Either the tag itself or a subtag of it. The trailing hyphen matters: without it
                // "engineering" would match "en", and "this" would match "th".
                if (candidate.Equals(prefix, StringComparison.Ordinal)
                    || candidate.StartsWith(prefix + "-", StringComparison.Ordinal))
                {
                    return canonical;
                }
            }
        }

        return Default;
    }
}
