using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Application.Ports.External;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// WeChat web OAuth over HTTP: <c>GET /sns/oauth2/access_token</c>, which despite the name is the
/// call that turns an authorization code into an openid.
/// <para>
/// There is no retry loop, no backoff and no timeout here: all of it lives in the standard
/// resilience handler configured in <c>DependencyInjection</c>, the same as
/// <see cref="NotificationHttpClient"/>. What is left is one job - turn WeChat's answer into this
/// service's error contract.
/// </para>
/// <para>
/// <b>The split that matters is "WeChat said no" against "WeChat did not answer".</b> The first is
/// a 400 the user can act on by signing in again; the second is a 502 that belongs on an upstream
/// dashboard. Collapsing them would tell every user their login code was bad during a WeChat
/// outage, and would hide the outage.
/// </para>
/// </summary>
public sealed class WechatHttpClient(
    HttpClient httpClient,
    IOptions<WechatOptions> options,
    ILogger<WechatHttpClient> logger) : IWechatClient
{
        // Read at the point of use, NOT in the constructor. IOptions<T>.Value is what runs
        // DataAnnotations validation, so reading it eagerly throws OptionsValidationException
        // while this type is merely being CONSTRUCTED - and SocialIdentityAppService takes all
        // four providers in its constructor, so one missing credential made every provider's
        // endpoint answer 500. Deferring the read means an unconfigured provider fails only on
        // its own endpoints. Value is cached after the first successful read, so this costs nothing.
    private WechatOptions _options => options.Value;

    public async Task<WechatCodeExchange> ExchangeCodeAsync(string code, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            throw new WechatRejectedException("A WeChat sign-in code is required.");
        }

        var path = "sns/oauth2/access_token"
                   + $"?appid={Uri.EscapeDataString(_options.AppId)}"
                   + $"&secret={Uri.EscapeDataString(_options.AppSecret)}"
                   + $"&code={Uri.EscapeDataString(code)}"
                   + "&grant_type=authorization_code";

        using var request = new HttpRequestMessage(HttpMethod.Get, path);

        var session = await WechatResponseReader.SendAsync(
            httpClient, request, WechatApiJson.Default.WechatSessionResponse, cancellationToken);

        return WechatSessions.Require(session, logger, "web OAuth");
    }
}

/// <summary>
/// The one rule both WeChat sign-in endpoints share: a 200 response is not a success.
/// </summary>
internal static class WechatSessions
{
    public static WechatCodeExchange Require(
        WechatSessionResponse session,
        ILogger logger,
        string flow)
    {
        if (session.ErrorCode != 0)
        {
            // WeChat's errmsg is written for developers and can name the AppID, so it goes to the
            // log; the code goes to the client, which is all it can act on anyway.
            logger.LogWarning(
                "WeChat refused a {Flow} code exchange: {ErrorCode} {ErrorMessage}.",
                flow,
                session.ErrorCode,
                WechatResponseReader.Truncate(session.ErrorMessage));

            throw new WechatRejectedException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"WeChat rejected the sign-in code (error {session.ErrorCode})."));
        }

        if (string.IsNullOrWhiteSpace(session.OpenId))
        {
            // A 200 with errcode 0 and no openid. Treated as a refusal rather than as a parse
            // failure, because the alternative is hashing the empty string into an identifier that
            // every such response would share - one account for everybody who ever hits this.
            logger.LogWarning("WeChat answered a {Flow} code exchange with no openid.", flow);

            throw new WechatRejectedException("WeChat returned no account identifier.");
        }

        return new WechatCodeExchange(session.OpenId, session.UnionId ?? string.Empty);
    }
}
