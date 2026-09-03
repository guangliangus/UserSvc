using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>
/// One entry of the context switcher, as a sign-in or <c>/back-office/tenants</c> reports it.
/// </summary>
/// <param name="TenantType">company | supplier.</param>
/// <param name="TenantCode">The tenant's code, or <c>*</c> for a whole-dimension entry.</param>
/// <param name="ScopeAll">Whether this entry is a whole dimension rather than one tenant.</param>
/// <param name="IsAdmin">Whether the member row behind it holds an admin role.</param>
internal sealed record TenantOption(string TenantType, string TenantCode, bool ScopeAll, bool IsAdmin);

/// <summary>
/// What <c>POST /api/v1/back-office/auth/login</c> answered, in the shape the assertions need.
/// <para>
/// Parsed field by field out of a <see cref="JsonDocument"/> rather than deserialized into
/// <c>BackOfficeSignInResponse</c>, following the convention <see cref="ProblemDetailsBody"/> and
/// <see cref="TokenResponse"/> already set here: the contract being tested is the JSON on the
/// wire - the property names a generated client will carry - and binding to the server's own type
/// would make a rename invisible to every test in this file.
/// </para>
/// </summary>
/// <param name="Status">The HTTP status.</param>
/// <param name="UserId">The back-office account id the sign-in resolved to.</param>
/// <param name="ContextRequired">Whether a context still has to be chosen. It decides which scope
/// the ticket produces, so it is the sign-in's whole verdict in one boolean.</param>
/// <param name="SignInTicket">The ticket to present at the token endpoint.</param>
/// <param name="TicketExpiresIn">Seconds the ticket stays redeemable.</param>
/// <param name="GrantedScope">The scope the ticket will produce, as the sign-in advertises it.</param>
/// <param name="IsGlobal">Whether the account holds whole-dimension access anywhere.</param>
/// <param name="Tenants">The contexts on offer.</param>
/// <param name="Root">The whole body, for assertions with no field of their own.</param>
internal sealed record BackOfficeSignInBody(
    HttpStatusCode Status,
    int UserId,
    bool ContextRequired,
    string SignInTicket,
    int TicketExpiresIn,
    string GrantedScope,
    bool IsGlobal,
    IReadOnlyList<TenantOption> Tenants,
    JsonElement Root);

/// <summary>
/// What <c>GET /api/v1/back-office/me</c> answered.
/// <para>
/// The three authority collections are nullable here because they are nullable on the wire and the
/// three states mean different things: a list is the answer, an empty list is "you hold nothing",
/// and null is "not delivered this time". Flattening null to empty in the reader would make the
/// one distinction this endpoint exists to carry untestable.
/// </para>
/// </summary>
/// <param name="Status">The HTTP status.</param>
/// <param name="UserId">The account the endpoint resolved from the token.</param>
/// <param name="ActiveTenantType">platform | global | company | supplier, or empty when the
/// session has no context.</param>
/// <param name="ActiveCompanyCode">The company code of the active context, or empty.</param>
/// <param name="IsTenantAdmin">Whether the member row behind the active context is an admin one.</param>
/// <param name="Roles">Role codes, or null when the snapshot was not delivered.</param>
/// <param name="Permissions">Permission codes, or null when the snapshot was not delivered.</param>
/// <param name="Menus">Menu codes, or null when the snapshot was not delivered.</param>
/// <param name="Tenants">The contexts on offer.</param>
internal sealed record BackOfficeMeBody(
    HttpStatusCode Status,
    int UserId,
    string ActiveTenantType,
    string ActiveCompanyCode,
    bool IsTenantAdmin,
    IReadOnlyList<string>? Roles,
    IReadOnlyList<string>? Permissions,
    IReadOnlyList<string>? Menus,
    IReadOnlyList<TenantOption> Tenants);

/// <summary>
/// Drives the back-office REST endpoints: the password door, the context chooser and the shell.
/// </summary>
internal static class BackOfficeEndpoints
{
    public static readonly Uri PasswordLoginPath =
        new("/api/v1/back-office/auth/login", UriKind.Relative);

    public static readonly Uri StaffOtpLoginPath =
        new("/api/v1/back-office/auth/otp-login", UriKind.Relative);

    public static readonly Uri TenantsPath = new("/api/v1/back-office/tenants", UriKind.Relative);

    public static readonly Uri ContextPath = new("/api/v1/back-office/context", UriKind.Relative);

    public static readonly Uri MePath = new("/api/v1/back-office/me", UriKind.Relative);

    /// <summary>
    /// Signs in at the password door and returns whatever came back - success or refusal.
    /// <para>
    /// It does not assert the status, because half the tests here are about the refusals and their
    /// bodies. The response message is handed back beside the parsed body so a caller can read the
    /// ProblemDetails off it, and is the caller's to dispose.
    /// </para>
    /// </summary>
    public static async Task<(BackOfficeSignInBody Body, HttpResponseMessage Response)> SignInAsync(
        HttpClient client, string email, string password)
    {
        ArgumentNullException.ThrowIfNull(client);

        var response = await client.PostAsJsonAsync(
            PasswordLoginPath, new { email, password });

        return (await ReadSignInAsync(response), response);
    }

    /// <summary>The full walk a real client makes: sign in, redeem the ticket, hold a token.</summary>
    public static async Task<(BackOfficeSignInBody SignIn, TokenResponse Tokens)> SignInAndRedeemAsync(
        HttpClient client, SeededOperator operatorAccount, string deviceId)
    {
        ArgumentNullException.ThrowIfNull(operatorAccount);

        var (signIn, response) = await SignInAsync(client, operatorAccount.Email, operatorAccount.Password);
        response.Dispose();

        var tokens = await TokenEndpoint.RedeemBackOfficeTicketAsync(
            client, signIn.SignInTicket, deviceId);

        return (signIn, tokens);
    }

    /// <summary>A client carrying an access token as its bearer credential.</summary>
    public static HttpClient Bearer(ServiceFixture fixture, string accessToken)
    {
        ArgumentNullException.ThrowIfNull(fixture);

        var client = fixture.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        return client;
    }

    public static async Task<BackOfficeMeBody> MeAsync(HttpClient client)
    {
        ArgumentNullException.ThrowIfNull(client);

        using var response = await client.GetAsync(MePath);
        var raw = await response.Content.ReadAsStringAsync();

        if (response.StatusCode != HttpStatusCode.OK)
        {
            return new BackOfficeMeBody(
                response.StatusCode, 0, string.Empty, string.Empty, false, null, null, null, []);
        }

        using var document = JsonDocument.Parse(raw);
        var root = document.RootElement;
        var activeTenant = Member(root, "activeTenant");

        return new BackOfficeMeBody(
            response.StatusCode,
            Member(Member(root, "user"), "id").ValueKind == JsonValueKind.Number
                ? Member(Member(root, "user"), "id").GetInt32()
                : 0,
            String(activeTenant, "type"),
            String(activeTenant, "companyCode"),
            Boolean(root, "isTenantAdmin"),
            StringsOrNull(root, "roles"),
            StringsOrNull(root, "permissions"),
            StringsOrNull(root, "menus"),
            TenantsOf(root));
    }

    private static async Task<BackOfficeSignInBody> ReadSignInAsync(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync();

        if (response.StatusCode != HttpStatusCode.OK)
        {
            return new BackOfficeSignInBody(
                response.StatusCode, 0, false, string.Empty, 0, string.Empty, false, [], default);
        }

        using var document = JsonDocument.Parse(raw);
        var root = document.RootElement.Clone();

        return new BackOfficeSignInBody(
            response.StatusCode,
            Member(root, "userId").ValueKind == JsonValueKind.Number ? Member(root, "userId").GetInt32() : 0,
            Boolean(root, "contextRequired"),
            String(root, "signInTicket"),
            Member(root, "ticketExpiresIn").ValueKind == JsonValueKind.Number
                ? Member(root, "ticketExpiresIn").GetInt32()
                : 0,
            String(root, "grantedScope"),
            Boolean(root, "isGlobal"),
            TenantsOf(root),
            root);
    }

    private static IReadOnlyList<TenantOption> TenantsOf(JsonElement root)
    {
        var tenants = Member(root, "tenants");

        return tenants.ValueKind != JsonValueKind.Array
            ? []
            : [.. tenants.EnumerateArray().Select(entry => new TenantOption(
                String(entry, "tenantType"),
                String(entry, "tenantCode"),
                Boolean(entry, "scopeAll"),
                Boolean(entry, "isAdmin")))];
    }

    private static JsonElement Member(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out var value)
            ? value
            : default;

    private static string String(JsonElement parent, string name) =>
        Member(parent, name) is { ValueKind: JsonValueKind.String } value
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private static bool Boolean(JsonElement parent, string name) =>
        Member(parent, name).ValueKind == JsonValueKind.True;

    /// <summary>An array as a list of strings; null when the member is absent or JSON null, which
    /// is the "not delivered" state <see cref="BackOfficeMeBody"/> has to be able to see.</summary>
    private static IReadOnlyList<string>? StringsOrNull(JsonElement parent, string name) =>
        Member(parent, name) is { ValueKind: JsonValueKind.Array } array
            ? [.. array.EnumerateArray().Select(entry => entry.GetString() ?? string.Empty)]
            : null;
}
