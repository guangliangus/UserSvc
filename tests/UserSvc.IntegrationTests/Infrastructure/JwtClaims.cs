using System.Buffers.Text;
using System.Text;
using System.Text.Json;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>
/// Reads claims out of an access token.
/// <para>
/// Access-token encryption is disabled on this server, so an access token is a plain RS256 JWT and
/// its payload segment can be read with no key at all - which is the point: downstream services
/// are meant to validate it as an ordinary bearer token. Refresh tokens are always encrypted JWEs,
/// opaque by design, and nothing here tries to decode one.
/// </para>
/// </summary>
internal static class JwtClaims
{
    public static string Subject(string accessToken) => Read(accessToken, "sub");

    public static string SessionId(string accessToken) => Read(accessToken, "sid");

    /// <summary>
    /// The granted scopes, read from either legal shape of the claim.
    /// <para>
    /// OpenIddict writes them into an access token as one space-delimited string, but a JWT may
    /// equally carry an array, and <c>BackOfficeAuthorization</c> deliberately reads both. A
    /// reader here that understood only one shape would let an assertion pass against a token the
    /// policies refuse, or refuse one they accept.
    /// </para>
    /// </summary>
    public static IReadOnlyList<string> Scopes(string accessToken)
    {
        var scope = Payload(accessToken, "scope");

        return scope.ValueKind switch
        {
            JsonValueKind.String => [.. (scope.GetString() ?? string.Empty).Split(
                ' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)],
            JsonValueKind.Array => [.. scope.EnumerateArray()
                .Select(entry => entry.GetString() ?? string.Empty)
                .Where(entry => entry.Length > 0)],
            _ => [],
        };
    }

    public static string Read(string accessToken, string claimType)
    {
        var value = Payload(accessToken, claimType);

        return value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : string.Empty;
    }

    /// <summary>The named payload member, or an undefined element when the token does not carry
    /// it. Undefined rather than null so "absent" and "present and null" stay distinguishable.</summary>
    private static JsonElement Payload(string accessToken, string claimType)
    {
        var segments = accessToken.Split('.');
        if (segments.Length != 3)
        {
            throw new InvalidOperationException(
                $"Expected a three-segment JWS access token but got {segments.Length} segment(s). "
                + "Access-token encryption must stay disabled or downstream services cannot read it.");
        }

        var payload = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(segments[1]));
        using var document = JsonDocument.Parse(payload);

        return document.RootElement.TryGetProperty(claimType, out var value)
            ? value.Clone()
            : default;
    }
}
