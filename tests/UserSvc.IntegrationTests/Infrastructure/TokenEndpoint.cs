using System.Globalization;
using System.Net;
using System.Text.Json;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>What the OAuth token endpoint answered, in the two shapes it ever answers in.</summary>
/// <param name="Status">The HTTP status.</param>
/// <param name="AccessToken">The access token, or empty on a failure.</param>
/// <param name="RefreshToken">The refresh token, or empty on a failure.</param>
/// <param name="Error">RFC 6749 <c>error</c>, or empty on success.</param>
/// <param name="ErrorDescription">RFC 6749 <c>error_description</c>, or empty on success.</param>
internal sealed record TokenResponse(
    HttpStatusCode Status,
    string AccessToken,
    string RefreshToken,
    string Error,
    string ErrorDescription)
{
    /// <summary>The <c>sid</c> claim carried by <see cref="AccessToken"/>, or empty on a failure.</summary>
    public string SessionId => AccessToken.Length == 0 ? string.Empty : JwtClaims.SessionId(AccessToken);
}

/// <summary>Drives <c>/connect/token</c>. It is a plain form POST rather than a typed client on
/// purpose: the point of these tests is that the wire contract is RFC 6749's, not ours.</summary>
internal static class TokenEndpoint
{
    public static readonly Uri Path = new("/connect/token", UriKind.Relative);

    public const string ClientId = "usersvc-app";

    /// <summary>The default of <c>AuthToken:DeviceGrantType</c>; the fixture does not override it.</summary>
    public const string DeviceGrantType = "urn:usersvc:params:oauth:grant-type:device";

    public static Task<TokenResponse> SignInDeviceAsync(
        HttpClient client,
        int userId,
        string deviceId,
        string deviceName = "Test Device",
        string platform = "IOS",
        string appVersion = "1.0.0",
        string? scope = null)
    {
        var form = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = DeviceGrantType,
            ["client_id"] = ClientId,
            ["user_id"] = userId.ToString(CultureInfo.InvariantCulture),
            ["device_id"] = deviceId,
            ["device_name"] = deviceName,
            ["platform"] = platform,
            ["app_version"] = appVersion,
        };

        if (scope is not null)
        {
            form["scope"] = scope;
        }

        return PostAsync(client, form);
    }

    public static Task<TokenResponse> RefreshAsync(HttpClient client, string refreshToken) =>
        PostAsync(client, new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = ClientId,
            ["refresh_token"] = refreshToken,
        });

    private static async Task<TokenResponse> PostAsync(HttpClient client, Dictionary<string, string> form)
    {
        using var content = new FormUrlEncodedContent(form);
        using var response = await client.PostAsync(Path, content);

        var body = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(body);

        return new TokenResponse(
            response.StatusCode,
            Read(document, "access_token"),
            Read(document, "refresh_token"),
            Read(document, "error"),
            Read(document, "error_description"));
    }

    private static string Read(JsonDocument document, string name) =>
        document.RootElement.TryGetProperty(name, out var value) ? value.GetString() ?? string.Empty : string.Empty;
}
