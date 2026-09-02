using System.Text.Json.Serialization;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The WeChat open-platform responses this service reads, and only the members it reads.
/// <para>
/// <b>Every one of them can carry <c>errcode</c> on an HTTP 200</b>, which is the single most
/// important thing to know about this API: WeChat answers 200 with a failure body far more often
/// than it answers a failure status. Code that branches on <see cref="HttpResponseMessage.IsSuccessStatusCode"/>
/// alone will happily treat "invalid code" as a successful sign-in with an empty openid.
/// </para>
/// </summary>
internal sealed record WechatErrorEnvelope
{
    [JsonPropertyName("errcode")]
    public int ErrorCode { get; init; }

    [JsonPropertyName("errmsg")]
    public string ErrorMessage { get; init; } = string.Empty;
}

/// <summary>Response of <c>/sns/oauth2/access_token</c> (web OAuth) and <c>/sns/jscode2session</c>.</summary>
internal sealed record WechatSessionResponse
{
    [JsonPropertyName("errcode")]
    public int ErrorCode { get; init; }

    [JsonPropertyName("errmsg")]
    public string ErrorMessage { get; init; } = string.Empty;

    [JsonPropertyName("openid")]
    public string OpenId { get; init; } = string.Empty;

    /// <summary>Absent unless the application is bound to an Open Platform account. Absent is normal.</summary>
    [JsonPropertyName("unionid")]
    public string UnionId { get; init; } = string.Empty;

    /// <summary>Mini program only. A credential: never logged, never stored, never returned.</summary>
    [JsonPropertyName("session_key")]
    public string SessionKey { get; init; } = string.Empty;
}

/// <summary>Response of <c>/cgi-bin/stable_token</c>.</summary>
internal sealed record WechatStableTokenResponse
{
    [JsonPropertyName("errcode")]
    public int ErrorCode { get; init; }

    [JsonPropertyName("errmsg")]
    public string ErrorMessage { get; init; } = string.Empty;

    [JsonPropertyName("access_token")]
    public string AccessToken { get; init; } = string.Empty;

    [JsonPropertyName("expires_in")]
    public int ExpiresInSeconds { get; init; }
}

/// <summary>Response of <c>/wxa/business/getuserphonenumber</c>.</summary>
internal sealed record WechatPhoneResponse
{
    [JsonPropertyName("errcode")]
    public int ErrorCode { get; init; }

    [JsonPropertyName("errmsg")]
    public string ErrorMessage { get; init; } = string.Empty;

    [JsonPropertyName("phone_info")]
    public WechatPhoneInfo? PhoneInfo { get; init; }
}

/// <summary>
/// The phone block. <c>phoneNumber</c> already includes the country code and
/// <c>purePhoneNumber</c> does not; this service builds E.164 from the pure number and the country
/// code, because the combined field's formatting has varied across WeChat's own releases.
/// </summary>
internal sealed record WechatPhoneInfo
{
    [JsonPropertyName("phoneNumber")]
    public string PhoneNumber { get; init; } = string.Empty;

    [JsonPropertyName("purePhoneNumber")]
    public string PurePhoneNumber { get; init; } = string.Empty;

    [JsonPropertyName("countryCode")]
    public string CountryCode { get; init; } = string.Empty;
}

/// <summary>Request body of <c>/cgi-bin/stable_token</c>.</summary>
internal sealed record WechatStableTokenRequest(
    [property: JsonPropertyName("grant_type")] string GrantType,
    [property: JsonPropertyName("appid")] string AppId,
    [property: JsonPropertyName("secret")] string Secret);

/// <summary>Request body of <c>/wxa/business/getuserphonenumber</c>.</summary>
internal sealed record WechatPhoneRequest([property: JsonPropertyName("code")] string Code);

[JsonSerializable(typeof(WechatErrorEnvelope))]
[JsonSerializable(typeof(WechatSessionResponse))]
[JsonSerializable(typeof(WechatStableTokenResponse))]
[JsonSerializable(typeof(WechatPhoneResponse))]
[JsonSerializable(typeof(WechatStableTokenRequest))]
[JsonSerializable(typeof(WechatPhoneRequest))]
internal sealed partial class WechatApiJson : JsonSerializerContext;
