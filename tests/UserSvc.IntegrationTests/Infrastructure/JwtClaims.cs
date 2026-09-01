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

    public static string Read(string accessToken, string claimType)
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
            ? value.GetString() ?? string.Empty
            : string.Empty;
    }
}
