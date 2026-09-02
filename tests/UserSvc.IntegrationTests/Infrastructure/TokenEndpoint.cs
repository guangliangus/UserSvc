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
/// <param name="Scope">
/// RFC 6749 <c>scope</c> as the token response stated it, space delimited, or empty when the
/// response stated none. It is <b>not</b> the authority: what a resource server acts on is the
/// scope claim inside the access token, which <see cref="GrantedScopes"/> reads.
/// </param>
/// <param name="ExpiresIn">
/// RFC 6749 <c>expires_in</c>, in seconds, or zero when the response stated none. This one is the
/// contract rather than a detail: it is the number a client sets its refresh timer from, so a
/// token whose <c>exp</c> and whose <c>expires_in</c> disagree gets used past its expiry.
/// </param>
internal sealed record TokenResponse(
    HttpStatusCode Status,
    string AccessToken,
    string RefreshToken,
    string Error,
    string ErrorDescription,
    string Scope = "",
    int ExpiresIn = 0)
{
    /// <summary>The <c>sid</c> claim carried by <see cref="AccessToken"/>, or empty on a failure.</summary>
    public string SessionId => AccessToken.Length == 0 ? string.Empty : JwtClaims.SessionId(AccessToken);

    /// <summary>
    /// The scopes the access token itself carries. Empty on a failure.
    /// <para>
    /// Read from the token rather than from the response body because that is the copy the
    /// authorization policies see: a grant that answered <c>scope=backoffice</c> while writing no
    /// scope claim into the token would satisfy an assertion on the body and be refused by every
    /// gated route.
    /// </para>
    /// </summary>
    public IReadOnlyList<string> GrantedScopes =>
        AccessToken.Length == 0 ? [] : JwtClaims.Scopes(AccessToken);

    /// <summary>The raw <c>act</c> claim carried by the access token, or empty when it carries
    /// none - which is what a pre-tenant token must look like.</summary>
    public string ActClaim => AccessToken.Length == 0 ? string.Empty : JwtClaims.Read(AccessToken, "act");
}

/// <summary>Drives <c>/connect/token</c>. It is a plain form POST rather than a typed client on
/// purpose: the point of these tests is that the wire contract is RFC 6749's, not ours.</summary>
internal static class TokenEndpoint
{
    public static readonly Uri Path = new("/connect/token", UriKind.Relative);

    public const string ClientId = "usersvc-app";

    /// <summary>The default of <c>AuthToken:DeviceGrantType</c>; the fixture does not override it.</summary>
    public const string DeviceGrantType = "urn:usersvc:params:oauth:grant-type:device";

    /// <summary>
    /// The grant that redeems a back-office sign-in ticket.
    /// <para>
    /// Spelled out as a literal rather than referenced from
    /// <c>BackOfficeTokenIssuer.SignInGrantType</c>, and that is deliberate: these two strings are
    /// the wire contract every back-office client is coded against, so a test that read them from
    /// the constant would keep passing if somebody renamed the URN and broke every deployed client.
    /// </para>
    /// </summary>
    public const string BackOfficeSignInGrantType = "urn:usersvc:params:oauth:grant-type:back-office";

    /// <summary>The grant that exchanges a back-office token for one carrying a chosen context.</summary>
    public const string BackOfficeContextGrantType =
        "urn:usersvc:params:oauth:grant-type:back-office-context";

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

    /// <summary>
    /// Redeems the ticket a back-office sign-in produced.
    /// <para>
    /// <paramref name="deviceId"/> is nullable rather than defaulted, and the difference is the
    /// contract: a full back-office token requires one and the grant refuses the request without
    /// it, while a pre-tenant redemption opens no device session and needs none. A defaulted
    /// parameter would have hidden both halves of that.
    /// </para>
    /// </summary>
    public static Task<TokenResponse> RedeemBackOfficeTicketAsync(
        HttpClient client,
        string signInTicket,
        string? deviceId = null,
        string deviceName = "Operator Laptop",
        string platform = "WEB",
        string appVersion = "1.0.0",
        string? scope = null)
    {
        var form = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = BackOfficeSignInGrantType,
            ["client_id"] = ClientId,
            ["sign_in_ticket"] = signInTicket,
        };

        AddDevice(form, deviceId, deviceName, platform, appVersion);

        if (scope is not null)
        {
            form["scope"] = scope;
        }

        return PostAsync(client, form);
    }

    /// <summary>
    /// Exchanges a back-office token - pre-tenant or full - for one carrying a chosen context. The
    /// presented credential travels as this client's bearer header, which is where the grant reads
    /// it from.
    /// </summary>
    public static Task<TokenResponse> ExchangeBackOfficeContextAsync(
        HttpClient client,
        string tenantType,
        string tenantCode,
        string? deviceId = null,
        string deviceName = "Operator Laptop",
        string platform = "WEB",
        string appVersion = "1.0.0")
    {
        var form = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = BackOfficeContextGrantType,
            ["client_id"] = ClientId,
            ["tenant_type"] = tenantType,
            ["tenant_code"] = tenantCode,
        };

        AddDevice(form, deviceId, deviceName, platform, appVersion);

        return PostAsync(client, form);
    }

    /// <summary>Posts an arbitrary form, for the malformed-request cases that have no well-formed
    /// helper by definition.</summary>
    public static Task<TokenResponse> PostFormAsync(
        HttpClient client, IReadOnlyDictionary<string, string> form)
    {
        ArgumentNullException.ThrowIfNull(form);

        return PostAsync(client, new Dictionary<string, string>(form, StringComparer.Ordinal));
    }

    private static void AddDevice(
        Dictionary<string, string> form,
        string? deviceId,
        string deviceName,
        string platform,
        string appVersion)
    {
        // Omitted entirely rather than sent empty when there is no device: an empty form field and
        // an absent one are the same to this grant today, and pinning the absent shape is the one
        // that matches a client that simply forgot the parameter.
        if (deviceId is null)
        {
            return;
        }

        form["device_id"] = deviceId;
        form["device_name"] = deviceName;
        form["platform"] = platform;
        form["app_version"] = appVersion;
    }

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
            Read(document, "error_description"),
            Read(document, "scope"),
            document.RootElement.TryGetProperty("expires_in", out var expiresIn)
             && expiresIn.ValueKind == JsonValueKind.Number
                ? expiresIn.GetInt32()
                : 0);
    }

    private static string Read(JsonDocument document, string name) =>
        document.RootElement.TryGetProperty(name, out var value) ? value.GetString() ?? string.Empty : string.Empty;
}
