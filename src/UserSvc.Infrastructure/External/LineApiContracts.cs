using System.Text.Json.Serialization;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The body of <c>POST /oauth2/v2.1/verify</c>: the decoded id_token claims on success, an OAuth
/// error object on failure. LINE uses HTTP status codes properly here, unlike WeChat, but the
/// error object is still checked because a 200 carrying <c>error</c> is cheaper to handle than to
/// prove impossible.
/// </summary>
internal sealed record LineVerifyResponse
{
    [JsonPropertyName("iss")]
    public string Issuer { get; init; } = string.Empty;

    [JsonPropertyName("sub")]
    public string Subject { get; init; } = string.Empty;

    [JsonPropertyName("aud")]
    public string Audience { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("picture")]
    public string Picture { get; init; } = string.Empty;

    /// <summary>Only present when the channel holds the <c>email</c> scope and the user consented.</summary>
    [JsonPropertyName("email")]
    public string Email { get; init; } = string.Empty;

    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;

    [JsonPropertyName("error_description")]
    public string ErrorDescription { get; init; } = string.Empty;
}

[JsonSerializable(typeof(LineVerifyResponse))]
internal sealed partial class LineApiJson : JsonSerializerContext;
