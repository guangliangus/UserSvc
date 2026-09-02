using System.Text.Json;

namespace UserSvc.Domain.Feedback;

/// <summary>
/// One selectable category in the feedback form's drop-down: a stable machine code plus its label
/// in every locale the apps ship in. Operations edit these rows directly; there is no management
/// API, by design.
/// </summary>
public sealed class FeedbackType
{
    /// <summary>
    /// The primary key, and the value the client submits. A text business key rather than the
    /// team's usual surrogate <c>SERIAL</c>: it is the live shape, <c>feedback.type_code</c> is a
    /// real foreign key onto it, and the code is part of the published API contract - moving to a
    /// surrogate key would change the foreign key and the wire contract at once for no gain.
    /// </summary>
    public string Code { get; set; } = string.Empty;

    /// <summary>
    /// <b>jsonb</b>: localized labels keyed by locale, for example
    /// <c>{"zh-CN":"...","en":"Bug report"}</c>. Held as raw JSON text - the live rows carry
    /// seven locales and flattening to one would throw away six. Read it with
    /// <see cref="ResolveLabel(string)"/>.
    /// </summary>
    public string Labels { get; set; } = EmptyLabelsJson;

    /// <summary>
    /// Only active types are listed, and only an active type is accepted on submit. This is the
    /// soft-delete: a retired category keeps its rows joinable while disappearing from the
    /// drop-down.
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>Ascending display order in the drop-down.</summary>
    public int SortOrder { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    /// <summary>Nullable, because the live column is: the four seeded rows carry no author. Kept
    /// nullable rather than tightened to <c>NOT NULL DEFAULT ''</c> so that the shape in the model
    /// and the shape in the database stay the same thing.</summary>
    public string? CreatedBy { get; set; }

    public string? UpdatedBy { get; set; }

    /// <summary>The database default, spelled the way the live column default is.</summary>
    public const string EmptyLabelsJson = "{}";

    /// <summary>The locale every other locale falls back to.</summary>
    public const string FallbackLocale = "en";

    /// <summary>
    /// The label for one locale: the exact match, then English, then the empty string.
    /// <para>
    /// <b>It never throws and the empty string is a legitimate answer.</b> A category whose labels
    /// are missing or malformed still belongs in the drop-down - the client can render the code -
    /// whereas a category list that fails to load leaves the form with nothing to choose from.
    /// </para>
    /// <para>
    /// Lookup is ordinal and case-sensitive, matching the way the locale keys are written in the
    /// seed: <c>zh-cn</c> is not <c>zh-CN</c>. Callers pass an already-normalized locale.
    /// </para>
    /// </summary>
    public string ResolveLabel(string locale)
    {
        var labels = ParseLabels();

        if (labels.TryGetValue(locale, out var label) && !string.IsNullOrEmpty(label))
        {
            return label;
        }

        return labels.TryGetValue(FallbackLocale, out var fallback) && !string.IsNullOrEmpty(fallback)
            ? fallback
            : string.Empty;
    }

    /// <summary>Locale map of this row. Anything unparseable reads as no labels at all.</summary>
    public IReadOnlyDictionary<string, string> ParseLabels() => ParseLabelsJson(Labels);

    /// <summary>
    /// Tolerant read of the <c>labels</c> payload; anything unparseable is an empty map. A payload
    /// that is valid JSON but not an object of strings - an array, a number, an object with a
    /// nested value - lands in the same place, which is why the catch covers
    /// <see cref="JsonException"/> rather than only malformed text.
    /// </summary>
    public static IReadOnlyDictionary<string, string> ParseLabelsJson(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, string>>(raw)
                   ?? new Dictionary<string, string>(StringComparer.Ordinal);
        }
        catch (JsonException)
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }
    }
}
