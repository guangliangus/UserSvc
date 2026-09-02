using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;
using StackExchange.Redis;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Infrastructure.External;
using UserSvc.Infrastructure.Platform;
using Xunit;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// The WeChat mini-program adapter: <c>code2Session</c>, the cached global access token, and the
/// phone-number redemption whose one hand-written retry is the subtlest thing in the slice.
/// </summary>
public sealed class WechatMiniHttpClientTests
{
    private readonly StubHttpMessageHandler _transport = new();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 10, 0, 0, TimeSpan.Zero));
    private readonly IDatabase _redis = Substitute.For<IDatabase>();

    public WechatMiniHttpClientTests()
    {
        // Redis is a soft dependency for this cache: an empty answer must degrade to a per-process
        // token rather than fail.
        _redis.StringGetAsync(Arg.Any<RedisKey>(), Arg.Any<CommandFlags>()).Returns(RedisValue.Null);
    }

    private WechatMiniAccessTokenCache Cache()
    {
        var connection = Substitute.For<IConnectionMultiplexer>();
        connection.GetDatabase().ReturnsForAnyArgs(_redis);

        return new WechatMiniAccessTokenCache(
            connection,
            Options.Create(new RedisOptions { Configuration = "localhost:6379", KeyPrefix = "test:" }),
            NullLogger<WechatMiniAccessTokenCache>.Instance);
    }

    private WechatMiniHttpClient Sut(WechatMiniAccessTokenCache? cache = null) => new(
        new HttpClient(_transport) { BaseAddress = new Uri("https://api.weixin.qq.com/") },
        cache ?? Cache(),
        Options.Create(new WechatMiniOptions { AppId = "mini-app", AppSecret = "mini-secret" }),
        _clock,
        NullLogger<WechatMiniHttpClient>.Instance);

    // ------------------------------------------------------------------ code2Session

    [Fact]
    public async Task Code2SessionReturnsTheOpenIdUnionIdAndSessionKey()
    {
        _transport.RespondsWithJsonAsTextPlain(
            """{"openid":"mini-open-1","unionid":"wx-union-1","session_key":"sk"}""");

        var session = await Sut().ExchangeSessionAsync("js-code-1", CancellationToken.None);

        session.OpenId.ShouldBe("mini-open-1");
        session.UnionId.ShouldBe("wx-union-1");
        session.SessionKey.ShouldBe("sk");
        _transport.Paths.ShouldHaveSingleItem().ShouldStartWith("/sns/jscode2session");
    }

    [Fact]
    public async Task ACode2SessionFailureBodyIsARefusal()
    {
        _transport.RespondsWithJsonAsTextPlain("""{"errcode":40029,"errmsg":"invalid code"}""");

        await Should.ThrowAsync<WechatRejectedException>(() =>
            Sut().ExchangeSessionAsync("js-code-1", CancellationToken.None));
    }

    // ------------------------------------------------------------------ phone number

    [Fact]
    public async Task ThePhoneNumberIsBuiltFromTheCountryCodeAndTheBareNumber()
    {
        _transport
            .RespondsWithJsonAsTextPlain("""{"access_token":"tok-1","expires_in":7200}""")
            .RespondsWithJsonAsTextPlain(
                """{"errcode":0,"phone_info":{"purePhoneNumber":"13900000000","countryCode":"86"}}""");

        var phone = await Sut().GetPhoneNumberAsync("phone-code-1", CancellationToken.None);

        phone.ShouldBe("+8613900000000");

        // The stable endpoint, not /cgi-bin/token: requesting a stable token does not invalidate
        // the one other services sharing this AppID are holding.
        _transport.Paths[0].ShouldBe("/cgi-bin/stable_token");
        _transport.Paths[1].ShouldStartWith("/wxa/business/getuserphonenumber?access_token=tok-1");

        // force_refresh is deliberately absent, so WeChat returns the currently valid token rather
        // than minting a new one on every call.
        _transport.Bodies[0].ShouldNotContain("force_refresh");
        _transport.Bodies[0].ShouldContain("client_credential");
    }

    /// <summary>
    /// The token is global per mini program and rate limited. Fetching it per request trips that
    /// limit under any real traffic, at which point nothing works at all.
    /// </summary>
    [Fact]
    public async Task TheAccessTokenIsFetchedOnceAndReusedAcrossCalls()
    {
        _transport
            .RespondsWithJsonAsTextPlain("""{"access_token":"tok-1","expires_in":7200}""")
            .RespondsWithJsonAsTextPlain(
                """{"errcode":0,"phone_info":{"purePhoneNumber":"13900000000","countryCode":"86"}}""")
            .RespondsWithJsonAsTextPlain(
                """{"errcode":0,"phone_info":{"purePhoneNumber":"13900000001","countryCode":"86"}}""");

        var cache = Cache();
        var sut = Sut(cache);

        await sut.GetPhoneNumberAsync("phone-code-1", CancellationToken.None);
        await sut.GetPhoneNumberAsync("phone-code-2", CancellationToken.None);

        _transport.Paths.Count(p => p == "/cgi-bin/stable_token").ShouldBe(1);
    }

    /// <summary>
    /// A cached token can be invalidated before its stated expiry - another service sharing this
    /// AppID refreshed it, or a deploy left one behind - and the only way to find out is to be told
    /// so by the call that used it. This is the case the standard resilience handler cannot cover,
    /// because the failure arrives as a 200.
    /// </summary>
    [Fact]
    public async Task AStaleAccessTokenIsDroppedAndTheCallRetriedExactlyOnce()
    {
        _transport
            .RespondsWithJsonAsTextPlain("""{"access_token":"tok-stale","expires_in":7200}""")
            .RespondsWithJsonAsTextPlain("""{"errcode":40001,"errmsg":"invalid credential"}""")
            .RespondsWithJsonAsTextPlain("""{"access_token":"tok-fresh","expires_in":7200}""")
            .RespondsWithJsonAsTextPlain(
                """{"errcode":0,"phone_info":{"purePhoneNumber":"13900000000","countryCode":"86"}}""");

        var phone = await Sut().GetPhoneNumberAsync("phone-code-1", CancellationToken.None);

        phone.ShouldBe("+8613900000000");
        _transport.Paths.Count(p => p == "/cgi-bin/stable_token").ShouldBe(2);
        _transport.Paths.Count(p => p.StartsWith("/wxa/business", StringComparison.Ordinal)).ShouldBe(2);
        _transport.Paths[3].ShouldContain("access_token=tok-fresh");
    }

    /// <summary>
    /// Exactly once. If a genuinely fresh token is also refused, the problem is not the token, and
    /// a second refresh would only spend the rate limit the cache exists to protect.
    /// </summary>
    [Fact]
    public async Task ARefusalThatSurvivesTheRefreshIsNotRetriedAgain()
    {
        _transport
            .RespondsWithJsonAsTextPlain("""{"access_token":"tok-1","expires_in":7200}""")
            .RespondsWithJsonAsTextPlain("""{"errcode":40001,"errmsg":"invalid credential"}""")
            .RespondsWithJsonAsTextPlain("""{"access_token":"tok-2","expires_in":7200}""")
            .RespondsWithJsonAsTextPlain("""{"errcode":40001,"errmsg":"invalid credential"}""");

        await Should.ThrowAsync<UpstreamException>(() =>
            Sut().GetPhoneNumberAsync("phone-code-1", CancellationToken.None));

        _transport.Paths.Count(p => p == "/cgi-bin/stable_token").ShouldBe(2);
    }

    /// <summary>
    /// Only the three token error codes justify a refresh. Retrying on anything else would double
    /// every genuine failure.
    /// </summary>
    [Fact]
    public async Task AnErrorThatIsNotATokenErrorIsNotRetried()
    {
        _transport
            .RespondsWithJsonAsTextPlain("""{"access_token":"tok-1","expires_in":7200}""")
            .RespondsWithJsonAsTextPlain("""{"errcode":40029,"errmsg":"invalid code"}""");

        await Should.ThrowAsync<UpstreamException>(() =>
            Sut().GetPhoneNumberAsync("phone-code-1", CancellationToken.None));

        _transport.Paths.Count(p => p == "/cgi-bin/stable_token").ShouldBe(1);
    }

    [Fact]
    public async Task AResponseWithNoPhoneNumberIsAFailureRatherThanAnEmptyNumber()
    {
        _transport
            .RespondsWithJsonAsTextPlain("""{"access_token":"tok-1","expires_in":7200}""")
            .RespondsWithJsonAsTextPlain("""{"errcode":0,"phone_info":{"countryCode":"86"}}""");

        await Should.ThrowAsync<UpstreamException>(() =>
            Sut().GetPhoneNumberAsync("phone-code-1", CancellationToken.None));
    }

    [Fact]
    public async Task ATokenEndpointFailureIsAnUpstreamFailure()
    {
        _transport.RespondsWithJsonAsTextPlain("""{"errcode":40013,"errmsg":"invalid appid"}""");

        await Should.ThrowAsync<UpstreamException>(() =>
            Sut().GetPhoneNumberAsync("phone-code-1", CancellationToken.None));
    }

    /// <summary>
    /// The cached lifetime is shorter than WeChat's, so a token is never handed out with seconds
    /// left on it and then rejected mid-flight by the very call that fetched it.
    /// </summary>
    [Fact]
    public async Task TheCachedTokenIsRetiredAheadOfWechatsOwnExpiry()
    {
        _transport
            .RespondsWithJsonAsTextPlain("""{"access_token":"tok-1","expires_in":7200}""")
            .RespondsWithJsonAsTextPlain(
                """{"errcode":0,"phone_info":{"purePhoneNumber":"13900000000","countryCode":"86"}}""");

        var cache = Cache();
        await cache.GetAsync(false, _ => Task.FromResult(("seed", TimeSpan.FromSeconds(1))), _clock.UtcNow, default);

        // Past the shortened TTL but well inside WeChat's own 7200 seconds.
        _clock.Advance(TimeSpan.FromSeconds(2));

        await Sut(cache).GetPhoneNumberAsync("phone-code-1", CancellationToken.None);

        _transport.Paths.Count(p => p == "/cgi-bin/stable_token").ShouldBe(1);
    }

    /// <summary>
    /// A cold start with many simultaneous sign-ins must produce one call to WeChat, not one per
    /// caller - that is the rate limit the cache exists for.
    /// </summary>
    [Fact]
    public async Task ConcurrentRefreshesCollapseIntoASingleFetch()
    {
        var cache = Cache();
        var fetches = 0;
        var release = new TaskCompletionSource();

        async Task<(string, TimeSpan)> Fetch(CancellationToken _)
        {
            Interlocked.Increment(ref fetches);
            await release.Task;

            return ("tok-1", TimeSpan.FromHours(1));
        }

        var waiters = Enumerable.Range(0, 16)
            .Select(_ => cache.GetAsync(false, Fetch, _clock.UtcNow, CancellationToken.None))
            .ToArray();

        release.SetResult();
        var tokens = await Task.WhenAll(waiters);

        fetches.ShouldBe(1);
        tokens.ShouldAllBe(t => t == "tok-1");
    }

    [Fact]
    public async Task ABlankPhoneCodeNeverReachesTheNetwork()
    {
        var thrown = await Should.ThrowAsync<BadRequestException>(() =>
            Sut().GetPhoneNumberAsync("  ", CancellationToken.None));

        thrown.ErrorCode.ShouldBe(ErrorCodes.WechatLoginFailed);
        _transport.Requests.ShouldBeEmpty();
    }

    // ------------------------------------------------------------------ E.164 assembly

    /// <summary>
    /// A number that already carries a plus is E.164 already; prefixing a country code onto it
    /// would produce something that is not a telephone number anywhere.
    /// </summary>
    [Theory]
    [InlineData("86", "13900000000", "+8613900000000")]
    [InlineData("+86", "13900000000", "+8613900000000")]
    [InlineData("", "13900000000", "+8613900000000")]
    [InlineData(null, "13900000000", "+8613900000000")]
    [InlineData("886", "912345678", "+886912345678")]
    [InlineData("86", "+8613900000000", "+8613900000000")]
    [InlineData("86", "  13900000000  ", "+8613900000000")]
    [InlineData("86", "", "")]
    [InlineData("86", null, "")]
    public void E164IsAssembledFromTheCountryCodeAndTheBareNumber(
        string? countryCode,
        string? pureNumber,
        string expected)
    {
        WechatMiniHttpClient.NormalizePhone(countryCode, pureNumber).ShouldBe(expected);
    }
}
