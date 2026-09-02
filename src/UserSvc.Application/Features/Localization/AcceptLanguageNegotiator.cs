using System.Globalization;

namespace UserSvc.Application.Features.Localization;

/// <summary>
/// Negotiates one of the seven supported locales out of an RFC 9110 <c>Accept-Language</c> header.
/// <para>
/// <b>The Go service did not do this, and the omission was reasonable there.</b> Its
/// <c>DeviceInfoRequired</c> middleware made <c>X-Language</c> mandatory on every route, so every
/// caller supplied one and a browser's automatic header was never the only signal. This service
/// deliberately does not make that header mandatory (see the request-context middleware for why),
/// which leaves <c>Accept-Language</c> as the only thing a browser sends unprompted. Honouring it
/// costs one header parse and is what makes an unmodified browser get its own language.
/// </para>
/// <para>
/// <c>X-Language</c> still wins whenever it is present: it is an explicit product decision by a
/// client that knows which language its own UI is in, and <c>Accept-Language</c> is the operating
/// system's guess.
/// </para>
/// </summary>
public static class AcceptLanguageNegotiator
{
    /// <summary>
    /// The best supported locale the header asks for, or <see langword="null"/> when it asks for
    /// nothing this service has text in.
    /// <para>
    /// Entries are ranked by their quality value, highest first, and ties keep the order the client
    /// wrote — <c>ja,en;q=0.9</c> is Japanese, and <c>en;q=0.5,ja;q=0.9</c> is Japanese too.
    /// A <c>q=0</c> entry is an explicit refusal and is dropped rather than ranked last. The
    /// wildcard <c>*</c> is ignored: it means "anything", which is not a request for a language and
    /// must not read as one.
    /// </para>
    /// </summary>
    public static string? Negotiate(string? headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return null;
        }

        var ranked = new List<(double Quality, int Order, string Locale)>();
        var order = 0;

        foreach (var entry in headerValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = entry.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length == 0)
            {
                continue;
            }

            var tag = parts[0];
            if (tag == "*" || !SupportedLocales.TryNormalize(tag, out var locale))
            {
                continue;
            }

            var quality = QualityOf(parts);
            if (quality <= 0)
            {
                continue;
            }

            ranked.Add((quality, order++, locale));
        }

        if (ranked.Count == 0)
        {
            return null;
        }

        ranked.Sort(static (left, right) =>
        {
            var byQuality = right.Quality.CompareTo(left.Quality);

            return byQuality != 0 ? byQuality : left.Order.CompareTo(right.Order);
        });

        return ranked[0].Locale;
    }

    /// <summary>
    /// The entry's <c>q</c> parameter, defaulting to 1. An unparseable one also defaults to 1
    /// rather than to zero: a malformed weight is a client bug, and dropping the language it names
    /// would answer that bug by silently switching the user's language.
    /// </summary>
    private static double QualityOf(string[] parts)
    {
        for (var i = 1; i < parts.Length; i++)
        {
            var parameter = parts[i];
            if (!parameter.StartsWith("q=", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return double.TryParse(
                parameter.AsSpan(2), NumberStyles.Float, CultureInfo.InvariantCulture, out var quality)
                ? quality
                : 1d;
        }

        return 1d;
    }
}
