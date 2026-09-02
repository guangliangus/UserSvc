using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace UserSvc.Application.Features.SocialIdentity;

/// <summary>
/// The small bag of provider-supplied context that rides along on a third-party login identity, in
/// the <c>provider_details</c> jsonb column.
/// <para>
/// <b>Why a jsonb column rather than three more columns:</b> every provider contributes a different
/// subset - WeChat has a union id and no name, LINE has a name and sometimes an address, Firebase
/// has both - and none of it is ever queried. It is displayed, or used to recognise which account
/// a masked address belongs to. Adding a nullable column per provider for data no index will ever
/// touch is how a table becomes unreadable.
/// </para>
/// <para>
/// <b>Nothing in here is a lookup key.</b> The WeChat union id is stored here <i>and</i> in
/// <c>provider_uid</c>, and the query that unifies two WeChat identities reads the column, not the
/// json - a partial index on a json expression would be a different index from the one the query
/// planner can use for the equality it actually performs.
/// </para>
/// </summary>
/// <param name="UnionId">WeChat's cross-app identifier for the same human. Empty for every other provider.</param>
/// <param name="EmailMasked">
/// Masked form of the address the provider reported. Never the address itself: the searchable copy
/// lives in a proper email identity row with its own blind index, and a second plaintext copy here
/// would be one more place to leak from and one more place to forget during a key rotation.
/// </param>
/// <param name="Name">Display name as the provider spelled it, kept for support and for audit.</param>
public sealed record ProviderDetails(
    [property: JsonPropertyName("union_id")] string UnionId = "",
    [property: JsonPropertyName("email_masked")] string EmailMasked = "",
    [property: JsonPropertyName("name")] string Name = "")
{
    /// <summary>What an identity with nothing worth recording stores: an empty object, never null.</summary>
    public const string EmptyJson = "{}";

    public static readonly ProviderDetails Empty = new();

    /// <summary>
    /// Serializes to the column value. Empty members are omitted, so a WeChat identity stores
    /// <c>{"union_id":"..."}</c> rather than three keys two of which are blank - the difference
    /// matters when a human is reading a row to work out what a provider actually returned.
    /// <para>
    /// Written by hand rather than through the serializer because
    /// <c>JsonIgnoreCondition.WhenWritingDefault</c> omits <see langword="null"/> and not the empty
    /// string, and making all three members nullable to buy that would push the null handling into
    /// every caller. Reading stays on the generated context, which tolerates whichever shape it
    /// finds.
    /// </para>
    /// </summary>
    public string ToJson()
    {
        if (this == Empty)
        {
            return EmptyJson;
        }

        var buffer = new ArrayBufferWriter<byte>();

        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            WriteIfPresent(writer, "union_id", UnionId);
            WriteIfPresent(writer, "email_masked", EmailMasked);
            WriteIfPresent(writer, "name", Name);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void WriteIfPresent(Utf8JsonWriter writer, string name, string value)
    {
        if (value.Length > 0)
        {
            writer.WriteString(name, value);
        }
    }

    /// <summary>
    /// Reads the column back.
    /// <para>
    /// <b>Malformed json answers <see cref="Empty"/> instead of throwing</b>, and that is a
    /// deliberate call about blast radius: this value is decoration on a login identity, and a row
    /// whose json was mangled by some past migration must not be able to stop its owner signing in.
    /// The lookup keys that decide anything are all real columns.
    /// </para>
    /// </summary>
    public static ProviderDetails FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Empty;
        }

        try
        {
            return JsonSerializer.Deserialize(json, SocialJson.Default.ProviderDetails) ?? Empty;
        }
        catch (JsonException)
        {
            return Empty;
        }
    }
}

/// <summary>
/// Provider values written to <c>user_identities.provider</c>.
/// <para>
/// <b>Web WeChat OAuth deliberately writes the empty string</b> while the mini program writes
/// <see cref="WechatMiniProgram"/>. The two are separate WeChat applications with separate openid
/// spaces, and the pair (identity_type, provider) is what keeps them apart; the empty value is the
/// original's and is preserved so existing rows keep matching.
/// </para>
/// </summary>
public static class SocialProviders
{
    /// <summary>Web OAuth, and every provider that has no sub-application concept.</summary>
    public const string None = "";

    /// <summary>The WeChat mini program.</summary>
    public const string WechatMiniProgram = "miniprogram";
}
