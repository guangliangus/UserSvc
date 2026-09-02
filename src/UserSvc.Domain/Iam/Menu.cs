using System.Text.Json;

namespace UserSvc.Domain.Iam;

/// <summary>
/// One node of the back-office sidebar registry, and the skeleton every permission point hangs
/// from. Deleting a menu is therefore a two-step operation (its permission points first), which is
/// what the <c>ON DELETE RESTRICT</c> on <c>permissions.menu_id</c> enforces.
/// </summary>
public sealed class Menu
{
    public int Id { get; set; }

    /// <summary>Stable menu code = the front-end sidebar key (for example <c>product-tour</c>).
    /// Immutable once live: it is baked into granted-menu sets and into the UI.</summary>
    public string Code { get; set; } = string.Empty;

    /// <summary>Parent menu; null = top-level group.</summary>
    public int? ParentId { get; set; }

    /// <summary>
    /// <b>jsonb</b>: localised names keyed by locale, e.g. <c>{"zh-TW":"...","en":"..."}</c>. Held
    /// as the raw JSON text rather than flattened to one string - the live rows carry seven locales
    /// and picking one here would throw the other six away. Read it with
    /// <see cref="ParseName"/>, write it with <see cref="BuildName"/>.
    /// </summary>
    public string Name { get; set; } = "{}";

    /// <summary>Route prefix; null for a pure grouping node.</summary>
    public string? Path { get; set; }

    public string? Icon { get; set; }

    public int SortOrder { get; set; }

    /// <summary><b>jsonb</b> string array of the tenant types that can see this menu:
    /// platform / company / supplier. A JSON array rather than <c>text[]</c> so no array driver
    /// mapping is needed on either side.</summary>
    public string Audience { get; set; } = DefaultAudienceJson;

    /// <summary>ACTIVE or INACTIVE. INACTIVE is the soft delete: it grants nothing, and its code is
    /// refused as unknown by the grant writer.</summary>
    public string Status { get; set; } = MenuStatuses.Active;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public string? CreatedBy { get; set; }

    public string? UpdatedBy { get; set; }

    /// <summary>The database default, spelled the same way the live column default is.</summary>
    public const string DefaultAudienceJson = """["platform", "company", "supplier"]""";

    public bool IsActive() => Status == MenuStatuses.Active;

    /// <summary>Locale map of this row. Never throws: a malformed or empty payload reads as no
    /// names at all, because a menu tree that fails to render is worse than one missing a label.</summary>
    public IReadOnlyDictionary<string, string> ParseName() => ParseNameJson(Name);

    /// <summary>Audience list of this row, empty on a malformed payload.</summary>
    public IReadOnlyList<string> ParseAudience() => ParseAudienceJson(Audience);

    /// <summary>Locale map -&gt; jsonb text. Ordered by key so two equal maps produce the same
    /// bytes and a no-op update stays a no-op.</summary>
    public static string BuildName(IReadOnlyDictionary<string, string> name) =>
        JsonSerializer.Serialize(name.OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal));

    /// <summary>Audience list -&gt; jsonb text, in the order given (already deduplicated by the
    /// caller, which is where the closed-set validation lives).</summary>
    public static string BuildAudience(IReadOnlyList<string> audience) =>
        JsonSerializer.Serialize(audience);

    /// <summary>Tolerant read of the <c>name</c> payload; anything unparseable is an empty map.</summary>
    public static IReadOnlyDictionary<string, string> ParseNameJson(string? raw)
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

    /// <summary>Tolerant read of the <c>audience</c> payload; anything unparseable is an empty
    /// list.</summary>
    public static IReadOnlyList<string> ParseAudienceJson(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<string>>(raw) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}

/// <summary>Closed set behind <c>chk_menus_status</c>. There is deliberately no PENDING or
/// DISABLED here - a menu is either in the registry or soft-deleted out of it.</summary>
public static class MenuStatuses
{
    public const string Active = "ACTIVE";
    public const string Inactive = "INACTIVE";

    public static bool IsValid(string? status) => status is Active or Inactive;
}

/// <summary>The tenant types a menu may declare itself for.</summary>
public static class MenuAudiences
{
    public const string Platform = "platform";
    public const string Company = "company";
    public const string Supplier = "supplier";

    public static readonly IReadOnlyList<string> All = [Platform, Company, Supplier];

    public static bool IsValid(string? audience) => audience is Platform or Company or Supplier;
}
