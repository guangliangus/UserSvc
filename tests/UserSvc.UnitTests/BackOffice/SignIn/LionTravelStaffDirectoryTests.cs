using System.Net;
using NSubstitute;
using StackExchange.Redis;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Infrastructure.External;
using UserSvc.Infrastructure.Platform;
using Xunit;

namespace UserSvc.UnitTests.BackOffice.SignIn;

/// <summary>
/// The corporate staff directory adapter.
/// <para>
/// <b>These tests pin an assumed contract.</b> The upstream's own specification was not available
/// when the adapter was written, so the paths, the request bodies, the field names and the checksum
/// recipe all come from a written description of it. Asserting them here is what turns a mismatch
/// into a failing test that names the field, instead of into "staff sign-in does not work" against
/// a live upstream. They are not proof the upstream agrees.
/// </para>
/// </summary>
public sealed class LionTravelStaffDirectoryTests
{
    private const string TokenBody =
        """
        {"Data":{"AccessToken":"basic abc123","CreateDateTime":"2026-09-02T09:00:00",
         "ExpireDateTime":"2026-09-02T10:00:00"},"rCode":"0000","rDesc":"ok"}
        """;

    private const string VerifiedBody =
        """
        {"Data":{"isVerified":true,"authResultCode":"0000","infoCode":"","authResultMsg":"ok"},
         "rCode":"0000"}
        """;

    private const string ProfileBody =
        """
        {"Data":{"StfnCode":"260022","StfnName":"Wang Xiaoming","StfnAlias":"wang.xm",
         "StfnEmail":"alice.chen@liontravel.com","StfnSts":"A","StfnDeptNo":"D01",
         "StfnDeptName":"Sales"},"rCode":"0000"}
        """;

    private readonly SocialIdentity.StubHttpMessageHandler _transport = new();
    private readonly RiskControl.FakeRedis _redis = new();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 9, 0, 0, TimeSpan.Zero));

    private LionTravelOptions _options = new()
    {
        TokenBaseAddress = "https://auth.example.com",
        OtpBaseAddress = "https://inc.example.com",
        HrBaseAddress = "https://hr.example.com",
        ApiKey = "key-1",
        ApiSecret = "secret-1",
    };

    /// <summary>
    /// A cache with no shared layer: the substituted Redis answers every read as a miss.
    /// <para>
    /// Used by the two expiry cases, because the in-memory Redis double expires entries by the
    /// wall clock while these tests move a <see cref="TestClock"/> - so a stale shared copy would
    /// answer for a window the process-local half has correctly let go of. What is under test here
    /// is the local window; Redis's own TTL is what expires the shared one.
    /// </para>
    /// </summary>
    private static LionTravelAccessTokenCache CacheWithoutSharedLayer()
    {
        var database = Substitute.For<IDatabase>();
        database.StringGetAsync(Arg.Any<RedisKey>(), Arg.Any<CommandFlags>())
            .Returns(RedisValue.Null);

        var connection = Substitute.For<IConnectionMultiplexer>();
        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object>()).Returns(database);

        return new LionTravelAccessTokenCache(
            connection,
            Options.Create(new RedisOptions { Configuration = "localhost:6379", KeyPrefix = "usersvc:" }),
            NullLogger<LionTravelAccessTokenCache>.Instance);
    }

    private LionTravelAccessTokenCache Cache => new(
        _redis.Connection,
        Options.Create(new RedisOptions { Configuration = "localhost:6379", KeyPrefix = "usersvc:" }),
        NullLogger<LionTravelAccessTokenCache>.Instance);

    private LionTravelStaffDirectory Sut(LionTravelAccessTokenCache? cache = null) => new(
        // No BaseAddress on purpose: the adapter builds absolute URIs because the upstream is three
        // hosts, and a base address would pin two thirds of the calls to the wrong one.
        new HttpClient(_transport),
        cache ?? Cache,
        Options.Create(_options),
        _clock,
        NullLogger<LionTravelStaffDirectory>.Instance);

    // ------------------------------------------------------------------ the assumed wire shape

    [Fact]
    public async Task AVerifiedCodeIsReportedAsVerifiedWithTheUpstreamsCodes()
    {
        _transport.RespondsWithJson(TokenBody).RespondsWithJson(VerifiedBody);

        var result = await Sut().VerifyOtpAsync("260022", "2449673", CancellationToken.None);

        result.IsVerified.ShouldBeTrue();
        result.ResultCode.ShouldBe("0000");
        result.ResultMessage.ShouldBe("ok");
    }

    [Fact]
    public async Task TheCodeIsPostedToTheOtpHostWithTheApplicationTokenVerbatim()
    {
        _transport.RespondsWithJson(TokenBody).RespondsWithJson(VerifiedBody);

        await Sut().VerifyOtpAsync("260022", "2449673", CancellationToken.None);

        _transport.Requests[0].RequestUri!.ToString()
            .ShouldBe("https://auth.example.com/v2/token/generator");
        _transport.Requests[1].RequestUri!.ToString()
            .ShouldBe("https://inc.example.com/api/V2/OTPLogin");

        // Verbatim, with no scheme prepended: the upstream's token already carries its own, and a
        // second one produces a 401 that looks like an expired token.
        _transport.Requests[1].Headers.GetValues("Authorization").ShouldHaveSingleItem()
            .ShouldBe("basic abc123");

        _transport.Bodies[1].ShouldContain("\"Stfn\":\"260022\"");
        _transport.Bodies[1].ShouldContain("\"Pswd\":\"2449673\"");
    }

    [Fact]
    public async Task TheTokenMintSendsTheKeyTheSecretAndAChecksum()
    {
        _transport.RespondsWithJson(TokenBody).RespondsWithJson(VerifiedBody);

        await Sut().VerifyOtpAsync("260022", "2449673", CancellationToken.None);

        _transport.Bodies[0].ShouldContain("\"ApiKey\":\"key-1\"");
        _transport.Bodies[0].ShouldContain("\"ApiSecret\":\"secret-1\"");
        _transport.Bodies[0].ShouldContain("\"Checksum\":");
    }

    /// <summary>
    /// The checksum is an MD5 digest followed by the nonce it was salted with - 64 hex characters,
    /// and a different value every time even at a fixed clock, because the nonce is random.
    /// </summary>
    [Fact]
    public void TheChecksumIsSixtyFourHexCharactersAndNeverRepeats()
    {
        var first = LionTravelStaffDirectory.BuildChecksum("key-1", "secret-1", _clock.UtcNow);
        var second = LionTravelStaffDirectory.BuildChecksum("key-1", "secret-1", _clock.UtcNow);

        first.Length.ShouldBe(64);
        first.ShouldAllBe(character => Uri.IsHexDigit(character));
        first.ShouldNotBe(second);
    }

    [Fact]
    public async Task TheHrProfileIsFetchedFromTheHrHostWithTheEmployeeNumberTwice()
    {
        _transport.RespondsWithJson(TokenBody).RespondsWithJson(ProfileBody);

        var profile = await Sut().GetStaffProfileAsync("260022", CancellationToken.None);

        _transport.Paths[1].ShouldBe(
            "/api/V2/Staff/StaffProfile?CultureID=zh_TW&StaffID=260022&UserID=260022");

        profile.StaffCode.ShouldBe("260022");
        profile.FullName.ShouldBe("Wang Xiaoming");
        profile.Alias.ShouldBe("wang.xm");
        profile.Email.ShouldBe("alice.chen@liontravel.com");
        profile.EmploymentStatus.ShouldBe("A");
        profile.DepartmentNo.ShouldBe("D01");
        profile.DepartmentName.ShouldBe("Sales");
    }

    // ------------------------------------------------------------------ the two kinds of failure

    /// <summary>
    /// A code the upstream examined and rejected is not an exception. The port promises callers may
    /// rely on the difference, because an outage reported as "wrong password" is invisible.
    /// </summary>
    [Fact]
    public async Task ARejectedCodeIsAResultAndNotAnException()
    {
        _transport
            .RespondsWithJson(TokenBody)
            .RespondsWithJson(
                """
                {"Data":{"isVerified":false,"authResultCode":"E401","infoCode":"EXPIRED",
                 "authResultMsg":"code expired"},"rCode":"0000"}
                """);

        var result = await Sut().VerifyOtpAsync("260022", "000000", CancellationToken.None);

        result.IsVerified.ShouldBeFalse();
        result.ResultCode.ShouldBe("E401");
        result.InfoCode.ShouldBe("EXPIRED");
    }

    /// <summary>
    /// A 200 with no result is the upstream saying "not verified" in its own way. It must never
    /// become a true, and it must not become an outage either - something did answer.
    /// </summary>
    [Fact]
    public async Task AnEmptyVerificationResultIsNotVerified()
    {
        _transport.RespondsWithJson(TokenBody).RespondsWithJson("""{"Data":null,"rCode":"9999"}""");

        var result = await Sut().VerifyOtpAsync("260022", "000000", CancellationToken.None);

        result.IsVerified.ShouldBeFalse();
        result.ResultCode.ShouldBe("9999");
    }

    [Fact]
    public async Task AFailedUpstreamStatusIsAnUpstreamFault()
    {
        _transport
            .RespondsWithJson(TokenBody)
            .RespondsWithJson("""{"error":"boom"}""", HttpStatusCode.InternalServerError);

        var failure = await Should.ThrowAsync<UpstreamException>(() =>
            Sut().VerifyOtpAsync("260022", "2449673", CancellationToken.None));

        failure.ErrorCode.ShouldBe(ErrorCodes.UpstreamUnavailable);
        failure.StatusCode.ShouldBe(502);

        // The message says nothing was checked, which is the one thing a caller must not get wrong.
        failure.Message.ShouldContain("nothing about the code you entered was checked", Case.Insensitive);
    }

    [Fact]
    public async Task ATransportFailureIsAnUpstreamFault()
    {
        _transport.RespondsWithJson(TokenBody).Throws(new HttpRequestException("connection refused"));

        await Should.ThrowAsync<UpstreamException>(() =>
            Sut().VerifyOtpAsync("260022", "2449673", CancellationToken.None));
    }

    [Fact]
    public async Task AnUnreadableBodyIsAnUpstreamFault()
    {
        _transport.RespondsWithJson(TokenBody).RespondsWithJson("not json at all");

        await Should.ThrowAsync<UpstreamException>(() =>
            Sut().VerifyOtpAsync("260022", "2449673", CancellationToken.None));
    }

    /// <summary>
    /// An HR record that does not exist is a 404, not a 502: the upstream answered and has no such
    /// employee. Reporting it as an outage would send an investigation at a vendor who is working.
    /// </summary>
    [Fact]
    public async Task AMissingHrRecordIsANotFound()
    {
        _transport.RespondsWithJson(TokenBody).RespondsWithJson("""{"Data":null,"rCode":"1001"}""");

        var failure = await Should.ThrowAsync<NotFoundException>(() =>
            Sut().GetStaffProfileAsync("999999", CancellationToken.None));

        failure.StatusCode.ShouldBe(404);
    }

    // ------------------------------------------------------------------ the application token

    /// <summary>
    /// Caching is a correctness requirement, not an optimisation: the mint endpoint is rate
    /// limited, so a mint per request stops working entirely under real traffic.
    /// </summary>
    [Fact]
    public async Task TheApplicationTokenIsMintedOnceAndReused()
    {
        _transport
            .RespondsWithJson(TokenBody)
            .RespondsWithJson(VerifiedBody)
            .RespondsWithJson(VerifiedBody);

        var cache = Cache;

        await Sut(cache).VerifyOtpAsync("260022", "2449673", CancellationToken.None);
        await Sut(cache).VerifyOtpAsync("260022", "2449673", CancellationToken.None);

        _transport.Paths.Count(path => path == "/v2/token/generator").ShouldBe(1);
    }

    /// <summary>
    /// A rejected token is re-minted and the call retried <b>once</b>. Looping would turn one
    /// expired token into a mint storm against the endpoint whose rate limit the cache exists for.
    /// </summary>
    [Fact]
    public async Task ARejectedTokenIsRefreshedAndTheCallRetriedOnce()
    {
        _transport
            .RespondsWithJson(TokenBody)
            .RespondsWithJson("""{"error":"unauthorized"}""", HttpStatusCode.Unauthorized)
            .RespondsWithJson(TokenBody)
            .RespondsWithJson(VerifiedBody);

        var result = await Sut().VerifyOtpAsync("260022", "2449673", CancellationToken.None);

        result.IsVerified.ShouldBeTrue();
        _transport.Paths.Count(path => path == "/v2/token/generator").ShouldBe(2);
        _transport.Paths.Count(path => path == "/api/V2/OTPLogin").ShouldBe(2);
    }

    /// <summary>A second 401 is not retried again - it becomes an upstream fault.</summary>
    [Fact]
    public async Task ASecondRejectionIsNotRetried()
    {
        _transport
            .RespondsWithJson(TokenBody)
            .RespondsWithJson("""{"error":"unauthorized"}""", HttpStatusCode.Unauthorized)
            .RespondsWithJson(TokenBody)
            .RespondsWithJson("""{"error":"unauthorized"}""", HttpStatusCode.Unauthorized);

        await Should.ThrowAsync<UpstreamException>(() =>
            Sut().VerifyOtpAsync("260022", "2449673", CancellationToken.None));
    }

    /// <summary>
    /// The cached window is the upstream's, minus a minute, so a token is never presented in the
    /// second it expires - a race that surfaces as one intermittent 401 per token lifetime.
    /// </summary>
    [Fact]
    public async Task TheCachedWindowStopsAMinuteShortOfTheUpstreamsExpiry()
    {
        // The stub answers in the order the calls are made: mint, check, check, mint, check.
        _transport
            .RespondsWithJson(TokenBody)
            .RespondsWithJson(VerifiedBody)
            .RespondsWithJson(VerifiedBody)
            .RespondsWithJson(TokenBody)
            .RespondsWithJson(VerifiedBody);

        var cache = CacheWithoutSharedLayer();

        await Sut(cache).VerifyOtpAsync("260022", "2449673", CancellationToken.None);

        // 58 minutes into a 60-minute window: still inside the shaved one.
        _clock.Advance(TimeSpan.FromMinutes(58));
        await Sut(cache).VerifyOtpAsync("260022", "2449673", CancellationToken.None);
        _transport.Paths.Count(path => path == "/v2/token/generator").ShouldBe(1);

        // Past 59 minutes, the shaved window is over and a fresh token is minted.
        _clock.Advance(TimeSpan.FromMinutes(2));
        await Sut(cache).VerifyOtpAsync("260022", "2449673", CancellationToken.None);
        _transport.Paths.Count(path => path == "/v2/token/generator").ShouldBe(2);
    }

    /// <summary>An unreadable validity window falls back to a short cache rather than to caching
    /// the token forever.</summary>
    [Fact]
    public async Task AnUnreadableValidityWindowFallsBackToAShortCache()
    {
        _transport
            .RespondsWithJson(
                """{"Data":{"AccessToken":"basic abc123","CreateDateTime":"","ExpireDateTime":""}}""")
            .RespondsWithJson(VerifiedBody)
            .RespondsWithJson(
                """{"Data":{"AccessToken":"basic abc123","CreateDateTime":"","ExpireDateTime":""}}""")
            .RespondsWithJson(VerifiedBody);

        var cache = CacheWithoutSharedLayer();

        await Sut(cache).VerifyOtpAsync("260022", "2449673", CancellationToken.None);
        _clock.Advance(TimeSpan.FromMinutes(6));
        await Sut(cache).VerifyOtpAsync("260022", "2449673", CancellationToken.None);

        _transport.Paths.Count(path => path == "/v2/token/generator").ShouldBe(2);
    }

    [Fact]
    public async Task ATokenMintWithNoTokenInItIsAnUpstreamFault()
    {
        _transport.RespondsWithJson("""{"Data":null,"rCode":"9001"}""");

        await Should.ThrowAsync<UpstreamException>(() =>
            Sut().VerifyOtpAsync("260022", "2449673", CancellationToken.None));
    }

    // ------------------------------------------------------------------ configuration

    /// <summary>
    /// A deployment that has not supplied the credentials is refused with 500
    /// <c>NOT_CONFIGURED</c> listing exactly which keys are absent - not <c>INTERNAL_ERROR</c>, so
    /// an operator looks at the secrets rather than at the code.
    /// </summary>
    [Fact]
    public async Task MissingConfigurationNamesEveryAbsentKey()
    {
        _options = new LionTravelOptions();

        var failure = await Should.ThrowAsync<AppException>(() =>
            Sut().VerifyOtpAsync("260022", "2449673", CancellationToken.None));

        failure.ErrorCode.ShouldBe(ErrorCodes.NotConfigured);
        failure.StatusCode.ShouldBe(500);
        failure.Message.ShouldContain("StaffDirectory:ApiKey");
        failure.Message.ShouldContain("StaffDirectory:ApiSecret");
        failure.Message.ShouldContain("StaffDirectory:TokenBaseAddress");
    }

    /// <summary>Nothing is asked of the upstream when the adapter knows it cannot be reached
    /// properly - the check runs before the first request.</summary>
    [Fact]
    public async Task MissingConfigurationSendsNoRequest()
    {
        _options = new LionTravelOptions { ApiKey = "key-1" };

        await Should.ThrowAsync<AppException>(() =>
            Sut().GetStaffProfileAsync("260022", CancellationToken.None));

        _transport.Requests.ShouldBeEmpty();
    }

    /// <summary>Constructing the adapter reads no options, so a deployment without the section can
    /// still build its container and serve every other door.</summary>
    [Fact]
    public void ConstructingTheAdapterWithNoConfigurationDoesNotThrow()
    {
        _options = new LionTravelOptions();

        Should.NotThrow(() => Sut());
    }

    /// <summary>A trailing slash on a base address is tolerated rather than doubling the separator
    /// - the adapter trims and joins.</summary>
    [Fact]
    public async Task ATrailingSlashOnABaseAddressIsTolerated()
    {
        _options = new LionTravelOptions
        {
            TokenBaseAddress = "https://auth.example.com",
            OtpBaseAddress = "https://inc.example.com/",
            HrBaseAddress = "https://hr.example.com",
            ApiKey = "key-1",
            ApiSecret = "secret-1",
        };
        _transport.RespondsWithJson(TokenBody).RespondsWithJson(VerifiedBody);

        await Sut().VerifyOtpAsync("260022", "2449673", CancellationToken.None);

        _transport.Requests[1].RequestUri!.ToString()
            .ShouldBe("https://inc.example.com/api/V2/OTPLogin");
    }
}
