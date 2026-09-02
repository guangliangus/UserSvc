using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The WeChat mini program over HTTP: <c>code2Session</c> for sign-in and
/// <c>getuserphonenumber</c> for the phone-number code the user tapped through.
/// <para>
/// Resilience - retries, backoff, timeouts, circuit breaker - lives in the standard handler
/// configured in <c>DependencyInjection</c>. The one retry written by hand here is a different
/// animal and is explained on <see cref="GetPhoneNumberAsync"/>.
/// </para>
/// </summary>
public sealed class WechatMiniHttpClient(
    HttpClient httpClient,
    WechatMiniAccessTokenCache tokenCache,
    IOptions<WechatMiniOptions> options,
    IClock clock,
    ILogger<WechatMiniHttpClient> logger) : IWechatMiniClient
{
    /// <summary>
    /// The three WeChat error codes that mean "this access token is no good", as opposed to "your
    /// request is no good": 40001 invalid or not-latest credential, 40014 invalid access_token,
    /// 42001 access_token expired. Only these justify dropping the cache and retrying - retrying on
    /// anything else would double every genuine failure.
    /// </summary>
    private static readonly int[] AccessTokenErrorCodes = [40001, 40014, 42001];

    /// <summary>
    /// Where the country code goes when WeChat reports none. The mini program's primary region is
    /// mainland China and a bare eleven-digit number from it is unambiguous there; guessing is
    /// still a guess, which is why it is a named constant rather than an inline literal.
    /// </summary>
    private const string DefaultCountryCode = "86";

        // Read at the point of use, NOT in the constructor. IOptions<T>.Value is what runs
        // DataAnnotations validation, so reading it eagerly throws OptionsValidationException
        // while this type is merely being CONSTRUCTED - and SocialIdentityAppService takes all
        // four providers in its constructor, so one missing credential made every provider's
        // endpoint answer 500. Deferring the read means an unconfigured provider fails only on
        // its own endpoints. Value is cached after the first successful read, so this costs nothing.
    private WechatMiniOptions _options => options.Value;

    public async Task<WechatMiniCodeExchange> ExchangeSessionAsync(
        string jsCode,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(jsCode))
        {
            throw new WechatRejectedException("A WeChat sign-in code is required.");
        }

        var path = "sns/jscode2session"
                   + $"?appid={Uri.EscapeDataString(_options.AppId)}"
                   + $"&secret={Uri.EscapeDataString(_options.AppSecret)}"
                   + $"&js_code={Uri.EscapeDataString(jsCode)}"
                   + "&grant_type=authorization_code";

        using var request = new HttpRequestMessage(HttpMethod.Get, path);

        var session = await WechatResponseReader.SendAsync(
            httpClient, request, WechatApiJson.Default.WechatSessionResponse, cancellationToken);

        var exchange = WechatSessions.Require(session, logger, "mini program");

        return new WechatMiniCodeExchange(exchange.OpenId, exchange.UnionId, session.SessionKey ?? string.Empty);
    }

    /// <summary>
    /// Redeem the phone-number code.
    /// <para>
    /// <b>The single hand-written retry is about staleness, not flakiness</b>, which is why the
    /// standard resilience handler cannot do it. A cached access token can be invalidated before
    /// its stated expiry - another service sharing this AppID refreshed it, or a deploy left one
    /// behind - and the only way to find out is to be told so by the call that used it. On one of
    /// the three token error codes the cache is dropped, a fresh token is forced, and the call is
    /// made once more. Exactly once: if a genuinely fresh token is also refused, the problem is not
    /// the token.
    /// </para>
    /// </summary>
    public async Task<string> GetPhoneNumberAsync(string phoneCode, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(phoneCode))
        {
            throw new BadRequestException(
                ErrorCodes.WechatLoginFailed, "A WeChat phone-number code is required.");
        }

        var response = await FetchPhoneAsync(phoneCode, forceRefresh: false, cancellationToken);

        if (Array.IndexOf(AccessTokenErrorCodes, response.ErrorCode) >= 0)
        {
            logger.LogWarning(
                "The cached WeChat mini-program access token was refused ({ErrorCode}); refreshing and retrying once.",
                response.ErrorCode);

            await tokenCache.InvalidateAsync();
            response = await FetchPhoneAsync(phoneCode, forceRefresh: true, cancellationToken);
        }

        if (response.ErrorCode != 0)
        {
            throw new UpstreamException(
                ErrorCodes.UpstreamUnavailable,
                "WeChat could not provide the phone number.",
                new InvalidOperationException(string.Create(
                    CultureInfo.InvariantCulture,
                    $"WeChat phone lookup failed: {response.ErrorCode} "
                    + $"{WechatResponseReader.Truncate(response.ErrorMessage)}")));
        }

        var phone = NormalizePhone(response.PhoneInfo?.CountryCode, response.PhoneInfo?.PurePhoneNumber);

        if (phone.Length == 0)
        {
            throw new UpstreamException(
                ErrorCodes.UpstreamUnavailable,
                "WeChat could not provide the phone number.",
                new InvalidOperationException("WeChat answered with no phone number."));
        }

        return phone;
    }

    /// <summary>
    /// Builds E.164 from the country code and the bare national number.
    /// <para>
    /// A number that already carries a <c>+</c> is left exactly as it is - it is already E.164, and
    /// prefixing a country code onto it would produce something that is not a telephone number
    /// anywhere. An empty country code falls back to <see cref="DefaultCountryCode"/>; an empty
    /// number produces an empty result, which the caller treats as "no phone number", never as
    /// "the number is blank".
    /// </para>
    /// </summary>
    public static string NormalizePhone(string? countryCode, string? pureNumber)
    {
        var number = pureNumber?.Trim() ?? string.Empty;
        if (number.Length == 0)
        {
            return string.Empty;
        }

        if (number.StartsWith('+'))
        {
            return number;
        }

        var country = countryCode?.Trim().TrimStart('+') ?? string.Empty;

        return "+" + (country.Length == 0 ? DefaultCountryCode : country) + number;
    }

    private async Task<WechatPhoneResponse> FetchPhoneAsync(
        string phoneCode,
        bool forceRefresh,
        CancellationToken cancellationToken)
    {
        var token = await tokenCache.GetAsync(
            forceRefresh, FetchAccessTokenAsync, clock.UtcNow, cancellationToken);

        using var request = WechatResponseReader.JsonPost(
            $"wxa/business/getuserphonenumber?access_token={Uri.EscapeDataString(token)}",
            new WechatPhoneRequest(phoneCode),
            WechatApiJson.Default.WechatPhoneRequest);

        return await WechatResponseReader.SendAsync(
            httpClient, request, WechatApiJson.Default.WechatPhoneResponse, cancellationToken);
    }

    /// <summary>
    /// Fetches through <c>/cgi-bin/stable_token</c> rather than <c>/cgi-bin/token</c>.
    /// <para>
    /// <b>The difference is not cosmetic.</b> <c>/cgi-bin/token</c> mints a new token and
    /// invalidates the one every other instance and every other service sharing this AppID is
    /// currently holding - so two services refreshing in the same minute knock each other over and
    /// the symptom is a stream of errcode 40001 that looks like a caching bug on our side. The
    /// stable endpoint returns the currently valid token instead, and <c>force_refresh</c> is
    /// deliberately left out so it stays that way.
    /// </para>
    /// </summary>
    private async Task<(string Token, TimeSpan Ttl)> FetchAccessTokenAsync(CancellationToken cancellationToken)
    {
        using var request = WechatResponseReader.JsonPost(
            "cgi-bin/stable_token",
            new WechatStableTokenRequest("client_credential", _options.AppId, _options.AppSecret),
            WechatApiJson.Default.WechatStableTokenRequest);

        var response = await WechatResponseReader.SendAsync(
            httpClient, request, WechatApiJson.Default.WechatStableTokenResponse, cancellationToken);

        if (response.ErrorCode != 0 || string.IsNullOrWhiteSpace(response.AccessToken))
        {
            throw new UpstreamException(
                ErrorCodes.UpstreamUnavailable,
                "WeChat could not issue an access token.",
                new InvalidOperationException(string.Create(
                    CultureInfo.InvariantCulture,
                    $"WeChat stable_token failed: {response.ErrorCode} "
                    + $"{WechatResponseReader.Truncate(response.ErrorMessage)}")));
        }

        // Retired early, so a token is never handed out with seconds left on it and then rejected
        // mid-flight by the very call that fetched it. A skew larger than the lifetime WeChat
        // reported would give a non-positive TTL, so the reported lifetime stands in that case.
        var lifetime = TimeSpan.FromSeconds(response.ExpiresInSeconds);
        var ttl = lifetime - _options.AccessTokenExpirySkew;

        return (response.AccessToken, ttl > TimeSpan.Zero ? ttl : lifetime);
    }
}
