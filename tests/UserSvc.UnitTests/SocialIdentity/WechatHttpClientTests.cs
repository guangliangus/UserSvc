using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Infrastructure.External;
using Xunit;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// The WeChat web OAuth adapter. Every case here is a real WeChat behaviour, and two of them are
/// the reason the adapter does not use the typed JSON reader or trust the HTTP status.
/// </summary>
public sealed class WechatHttpClientTests
{
    private readonly StubHttpMessageHandler _transport = new();

    private WechatHttpClient Sut => new(
        new HttpClient(_transport) { BaseAddress = new Uri("https://api.weixin.qq.com/") },
        Options.Create(new WechatOptions { AppId = "wx-app", AppSecret = "wx-secret" }),
        NullLogger<WechatHttpClient>.Instance);

    /// <summary>
    /// WeChat serves JSON under <c>Content-Type: text/plain</c>. A typed JSON reader validates the
    /// media type first and throws, so a response that parses perfectly well would surface as an
    /// unhandled 500.
    /// </summary>
    [Fact]
    public async Task JsonServedAsTextPlainIsStillParsed()
    {
        _transport.RespondsWithJsonAsTextPlain(
            """{"access_token":"at","openid":"wx-open-1","unionid":"wx-union-1","expires_in":7200}""");

        var exchange = await Sut.ExchangeCodeAsync("code-1", CancellationToken.None);

        exchange.OpenId.ShouldBe("wx-open-1");
        exchange.UnionId.ShouldBe("wx-union-1");
    }

    [Fact]
    public async Task TheCodeAndCredentialsGoOnTheQueryStringUrlEncoded()
    {
        _transport.RespondsWithJsonAsTextPlain("""{"openid":"wx-open-1"}""");

        await Sut.ExchangeCodeAsync("code with spaces", CancellationToken.None);

        var path = _transport.Paths.ShouldHaveSingleItem();
        path.ShouldStartWith("/sns/oauth2/access_token");
        path.ShouldContain("appid=wx-app");
        path.ShouldContain("code=code%20with%20spaces");
        path.ShouldContain("grant_type=authorization_code");
    }

    /// <summary>
    /// The single most important thing about this API: WeChat answers HTTP 200 with a failure body
    /// far more often than it answers a failure status. Branching on the status alone would treat
    /// "invalid code" as a successful sign-in with an empty openid.
    /// </summary>
    [Fact]
    public async Task AFailureBodyOnAHttp200IsARefusal()
    {
        _transport.RespondsWithJsonAsTextPlain("""{"errcode":40029,"errmsg":"invalid code"}""");

        var thrown = await Should.ThrowAsync<WechatRejectedException>(() =>
            Sut.ExchangeCodeAsync("code-1", CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.WechatLoginFailed);
        thrown.StatusCode.ShouldBe(400);

        // WeChat's errmsg can name the AppID, so it stays in the log; the numeric code is what the
        // client can act on.
        thrown.Message.ShouldContain("40029");
        thrown.Message.ShouldNotContain("wx-secret");
    }

    /// <summary>
    /// Errcode 0 and no openid. Treated as a refusal rather than a parse failure, because the
    /// alternative is hashing the empty string into an identifier that every such response shares -
    /// one account for everybody who ever hits it.
    /// </summary>
    [Fact]
    public async Task ASuccessBodyWithNoOpenIdIsARefusal()
    {
        _transport.RespondsWithJsonAsTextPlain("""{"access_token":"at","expires_in":7200}""");

        await Should.ThrowAsync<WechatRejectedException>(() =>
            Sut.ExchangeCodeAsync("code-1", CancellationToken.None));
    }

    [Fact]
    public async Task ABlankCodeNeverReachesTheNetwork()
    {
        await Should.ThrowAsync<WechatRejectedException>(() =>
            Sut.ExchangeCodeAsync("  ", CancellationToken.None));

        _transport.Requests.ShouldBeEmpty();
    }

    /// <summary>
    /// A refusal is the caller's problem; an unreachable WeChat is not. Collapsing the two would
    /// tell every user their login code was bad during a WeChat outage - and hide the outage.
    /// </summary>
    [Fact]
    public async Task AnUnreachableWechatIsAnUpstreamFailure()
    {
        _transport.Throws(new HttpRequestException("connection refused"));

        var thrown = await Should.ThrowAsync<UpstreamException>(() =>
            Sut.ExchangeCodeAsync("code-1", CancellationToken.None));

        thrown.StatusCode.ShouldBe(502);
    }

    [Fact]
    public async Task AGatewayErrorIsAnUpstreamFailure()
    {
        _transport.RespondsWithJsonAsTextPlain("<html>502</html>", HttpStatusCode.BadGateway);

        await Should.ThrowAsync<UpstreamException>(() =>
            Sut.ExchangeCodeAsync("code-1", CancellationToken.None));
    }

    [Fact]
    public async Task AnUnparseableBodyIsAnUpstreamFailure()
    {
        _transport.RespondsWithJsonAsTextPlain("not json at all");

        await Should.ThrowAsync<UpstreamException>(() =>
            Sut.ExchangeCodeAsync("code-1", CancellationToken.None));
    }
}
