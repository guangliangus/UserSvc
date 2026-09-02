using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using StackExchange.Redis;
using UserSvc.Application.Ports.Platform;
using UserSvc.Infrastructure.Platform;
using Xunit;

namespace UserSvc.UnitTests.Platform;

/// <summary>
/// The key layout and the fail-open path, both without a Redis. The layout matters because a
/// collision silently merges two budgets and nothing reports it; the fail-open path matters because
/// getting it wrong turns a Redis blip into an outage of every endpoint the limiter guards.
/// </summary>
public sealed class RedisRateLimiterTests
{
    private const string Prefix = "usersvc:";

    private readonly IDatabase _database = Substitute.For<IDatabase>();
    private readonly IConnectionMultiplexer _connection = Substitute.For<IConnectionMultiplexer>();

    public RedisRateLimiterTests() =>
        _connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(_database);

    private static RedisRateLimiter Sut(IConnectionMultiplexer connection) => new(
        connection,
        Options.Create(new RedisOptions { Configuration = "localhost:6379", KeyPrefix = Prefix }),
        NullLogger<RedisRateLimiter>.Instance);

    [Fact]
    public void TheKeyCarriesThePrefixTheDimensionTheWindowAndTheHashedSubject()
    {
        var expectedSubject = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("203.0.113.7")));

        var key = RedisRateLimiter.BuildKey(Prefix, "login-ip", "203.0.113.7", TimeSpan.FromMinutes(1));

        key.ShouldBe($"usersvc:ratelimit:login-ip:60s:{expectedSubject}");
    }

    /// <summary>
    /// The raw subject never reaches the key. It is not a privacy control - a phone number is
    /// enumerable against a plain digest - but identifiers should not travel further than they
    /// have to, and a fixed-length digest is also what makes the layout unambiguous.
    /// </summary>
    [Fact]
    public void TheSubjectItselfNeverAppearsInTheKey()
    {
        RedisRateLimiter.BuildKey(Prefix, "send-code-target", "+886912345678", TimeSpan.FromMinutes(1))
            .ShouldNotContain("886912345678");
    }

    /// <summary>
    /// A per-minute and a per-hour limit on one subject are two budgets. Sharing a counter would
    /// let whichever TTL landed last decide when both reset.
    /// </summary>
    [Fact]
    public void TwoWindowsOnTheSameSubjectAreTwoCounters()
    {
        var perMinute = RedisRateLimiter.BuildKey(Prefix, "login-ip", "203.0.113.7", TimeSpan.FromMinutes(1));
        var perHour = RedisRateLimiter.BuildKey(Prefix, "login-ip", "203.0.113.7", TimeSpan.FromHours(1));

        perMinute.ShouldNotBe(perHour);
        perHour.ShouldStartWith("usersvc:ratelimit:login-ip:3600s:");
    }

    [Fact]
    public void TwoDimensionsNeverShareASubjectsBudget()
    {
        RedisRateLimiter.BuildKey(Prefix, "login-ip", "203.0.113.7", TimeSpan.FromMinutes(1))
            .ShouldNotBe(RedisRateLimiter.BuildKey(Prefix, "password-reset-ip", "203.0.113.7", TimeSpan.FromMinutes(1)));
    }

    /// <summary>Whitespace and case are not a way to buy a second budget.</summary>
    [Fact]
    public void TheSubjectIsNormalizedBeforeItIsHashed()
    {
        RedisRateLimiter.BuildKey(Prefix, "send-code-target", "  User@Example.com ", TimeSpan.FromMinutes(1))
            .ShouldBe(RedisRateLimiter.BuildKey(Prefix, "send-code-target", "user@example.com", TimeSpan.FromMinutes(1)));
    }

    /// <summary>
    /// Rejecting ':' is what makes the layout injective: with it allowed, dimension "a:b" and
    /// dimension "a" with a window token of "b" could spell one key.
    /// </summary>
    [Fact]
    public void ADimensionContainingTheSeparatorIsRefused() =>
        Should.Throw<ArgumentException>(
            () => RedisRateLimiter.BuildKey(Prefix, "login:ip", "203.0.113.7", TimeSpan.FromMinutes(1)));

    /// <summary>
    /// The layout tests above prove <see cref="RedisRateLimiter.BuildKey"/> is right; this one
    /// proves the adapter actually counts into it. Without it the key could be computed correctly
    /// and then ignored, and every layout assertion above would still pass while two limits shared
    /// a bucket in production.
    /// <para>
    /// It also pins the script's only argument as the window in <b>milliseconds</b>. PEXPIRE takes
    /// milliseconds and EXPIRE takes seconds; passing 60 to PEXPIRE would expire every counter
    /// 60 ms after it was created, which reads as "the limiter does nothing" and nothing would say
    /// why.
    /// </para>
    /// </summary>
    [Fact]
    public async Task TheRequestIsCountedIntoTheKeyBuildKeyComputesWithTheWindowInMilliseconds()
    {
        ScriptReturns(RedisResult.Create([(RedisValue)1L, (RedisValue)60_000L]));

        await Sut(_connection).TryAcquireAsync(
            "login-ip",
            "203.0.113.7",
            RateLimitPolicy.PerMinute(5),
            CancellationToken.None);

        await _database.Received(1).ScriptEvaluateAsync(
            Arg.Any<string>(),
            Arg.Is<RedisKey[]>(keys =>
                keys.Length == 1
                && keys[0].ToString() == RedisRateLimiter.BuildKey(
                    Prefix, "login-ip", "203.0.113.7", TimeSpan.FromMinutes(1))),
            Arg.Is<RedisValue[]>(values => values.Length == 1 && (long)values[0] == 60_000L),
            Arg.Any<CommandFlags>());
    }

    /// <summary>
    /// The ordinary case, which the refusal tests below would let regress unnoticed: a count under
    /// the limit is served, and it spends exactly one unit of budget.
    /// </summary>
    [Fact]
    public async Task ACountUnderTheLimitIsAllowedAndSpendsOneUnit()
    {
        ScriptReturns(RedisResult.Create([(RedisValue)2L, (RedisValue)45_000L]));

        var decision = await Sut(_connection).TryAcquireAsync(
            "login-ip",
            "203.0.113.7",
            RateLimitPolicy.PerMinute(5),
            CancellationToken.None);

        decision.Allowed.ShouldBeTrue();
        decision.Remaining.ShouldBe(3);
    }

    [Fact]
    public async Task TheCounterValueAndTheRemainingTtlDecideTheOutcome()
    {
        ScriptReturns(RedisResult.Create([(RedisValue)6L, (RedisValue)30_000L]));

        var decision = await Sut(_connection).TryAcquireAsync(
            "login-ip",
            "203.0.113.7",
            RateLimitPolicy.PerMinute(5),
            CancellationToken.None);

        decision.Allowed.ShouldBeFalse();
        decision.RetryAfter.ShouldBe(TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// PTTL answers -1 for a key with no expiry and -2 for one that has vanished. Neither is a
    /// deadline, and neither may reach the client as a negative Retry-After.
    /// </summary>
    [Fact]
    public async Task AKeyWithNoReadableDeadlineFallsBackToTheWindow()
    {
        ScriptReturns(RedisResult.Create([(RedisValue)9L, (RedisValue)(-1L)]));

        var decision = await Sut(_connection).TryAcquireAsync(
            "login-ip",
            "203.0.113.7",
            RateLimitPolicy.PerMinute(5),
            CancellationToken.None);

        decision.Allowed.ShouldBeFalse();
        decision.RetryAfter.ShouldBe(TimeSpan.FromMinutes(1));
    }

    /// <summary>
    /// A connection failure allows the request. The alternative - refusing - would convert a Redis
    /// outage into an outage of login, sign-up and verification codes at once.
    /// </summary>
    [Fact]
    public async Task AConnectionFailureAllowsTheRequest()
    {
        ScriptThrows(new RedisConnectionException(
            ConnectionFailureType.SocketFailure,
            CommandFlags.None,
            "redis is down",
            null,
            CommandStatus.Unknown));

        var decision = await Sut(_connection).TryAcquireAsync(
            "login-ip",
            "203.0.113.7",
            RateLimitPolicy.PerMinute(5),
            CancellationToken.None);

        decision.Allowed.ShouldBeTrue();
        decision.Remaining.ShouldBe(5);
    }

    /// <summary>
    /// The one every "catch (RedisException)" gets wrong: RedisTimeoutException derives from
    /// TimeoutException, not from RedisException. A slow Redis is exactly the case fail-open is
    /// for, so this must not escape as a 500.
    /// </summary>
    [Fact]
    public async Task ATimeoutAllowsTheRequestToo()
    {
        ScriptThrows(new RedisTimeoutException(CommandFlags.None, "timed out", CommandStatus.WaitingToBeSent));

        var decision = await Sut(_connection).TryAcquireAsync(
            "login-ip",
            "203.0.113.7",
            RateLimitPolicy.PerMinute(5),
            CancellationToken.None);

        decision.Allowed.ShouldBeTrue();
    }

    /// <summary>
    /// A malformed reply is a defect in the script, not a Redis fault - but the limiter still lets
    /// the request through rather than 500-ing the endpoint it is only meant to protect.
    /// </summary>
    [Fact]
    public async Task AnUnexpectedReplyShapeAlsoFailsOpen()
    {
        ScriptReturns(RedisResult.Create((RedisValue)"nonsense"));

        var decision = await Sut(_connection).TryAcquireAsync(
            "login-ip",
            "203.0.113.7",
            RateLimitPolicy.PerMinute(5),
            CancellationToken.None);

        decision.Allowed.ShouldBeTrue();
    }

    [Fact]
    public async Task AnAlreadyCancelledCallDoesNotTouchRedis()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Should.ThrowAsync<OperationCanceledException>(() => Sut(_connection).TryAcquireAsync(
            "login-ip",
            "203.0.113.7",
            RateLimitPolicy.PerMinute(5),
            cancelled.Token));

        await _database.DidNotReceiveWithAnyArgs().ScriptEvaluateAsync(
            default(string)!,
            default,
            default,
            default);
    }

    /// <summary>
    /// The fourth failure shape, and the one no reading of the exception hierarchy would suggest.
    /// Observed live: the first <c>ScriptEvaluateAsync</c> a freshly started process issues threw
    /// <see cref="TaskCanceledException"/> while the multiplexer was still connecting under a
    /// 500 ms async timeout, and the back-office sign-in it was protecting answered
    /// 500 <c>INTERNAL_ERROR</c>. A limiter that 500s the endpoint it guards is precisely what
    /// fail-open exists to prevent, and it happened on the first login after every deployment.
    /// </summary>
    [Fact]
    public async Task ACancellationRedisRaisedOnItsOwnAllowsTheRequest()
    {
        ScriptThrows(new TaskCanceledException("A task was canceled."));

        var decision = await Sut(_connection).TryAcquireAsync(
            "login-ip",
            "203.0.113.7",
            RateLimitPolicy.PerMinute(5),
            CancellationToken.None);

        decision.Allowed.ShouldBeTrue();
    }

    /// <summary>
    /// And the other half of that guard: a cancellation that came from the <i>caller's</i> token is
    /// theirs to see. Swallowing it into a rate-limit decision nobody will read would hide a client
    /// disconnecting behind a limiter warning.
    /// </summary>
    [Fact]
    public async Task ACancellationTheCallerAskedForIsNotSwallowed()
    {
        using var source = new CancellationTokenSource();

        _database.ScriptEvaluateAsync(
                Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>())
            .Returns<Task<RedisResult>>(_ =>
            {
                // Cancelled from inside the call, which is what a client disconnecting mid-command
                // looks like: the token is already cancelled by the time the catch clause looks.
                source.Cancel();
                throw new TaskCanceledException("A task was canceled.");
            });

        await Should.ThrowAsync<TaskCanceledException>(() => Sut(_connection).TryAcquireAsync(
            "login-ip", "203.0.113.7", RateLimitPolicy.PerMinute(5), source.Token));
    }

    // ------------------------------------------------------------------ the read-only check

    /// <summary>
    /// A peek reads the counter it would have incremented, and does not increment it. Reading a
    /// different key than <c>TryAcquireAsync</c> writes would produce a gate that refuses nobody,
    /// with nothing to say why.
    /// </summary>
    [Fact]
    public async Task APeekReadsTheSameKeyTheCounterIsWrittenTo()
    {
        ScriptReturns(RedisResult.Create([(RedisValue)3L, (RedisValue)45_000L]));

        await Sut(_connection).PeekAsync(
            "login-ip", "203.0.113.7", RateLimitPolicy.PerMinute(5), CancellationToken.None);

        await _database.Received(1).ScriptEvaluateAsync(
            Arg.Is<string>(script => !script.Contains("INCR", StringComparison.Ordinal)),
            Arg.Is<RedisKey[]>(keys =>
                keys.Length == 1
                && keys[0].ToString() == RedisRateLimiter.BuildKey(
                    Prefix, "login-ip", "203.0.113.7", TimeSpan.FromMinutes(1))),
            Arg.Any<RedisValue[]>(),
            Arg.Any<CommandFlags>());
    }

    /// <summary>
    /// A peek answers for the request that would come next: with the limit reached it refuses,
    /// because the caller is asking in order to decide whether to serve one more. Answering on the
    /// stored count would make "5 per minute" serve six.
    /// </summary>
    [Theory]
    [InlineData(0L, true, 4)]
    [InlineData(4L, true, 0)]
    [InlineData(5L, false, 0)]
    [InlineData(9L, false, 0)]
    public async Task APeekAnswersForTheRequestThatWouldComeNext(long stored, bool allowed, int remaining)
    {
        ScriptReturns(RedisResult.Create([(RedisValue)stored, (RedisValue)30_000L]));

        var decision = await Sut(_connection).PeekAsync(
            "login-ip", "203.0.113.7", RateLimitPolicy.PerMinute(5), CancellationToken.None);

        decision.Allowed.ShouldBe(allowed);
        decision.Remaining.ShouldBe(remaining);

        if (!allowed)
        {
            decision.RetryAfter.ShouldBe(TimeSpan.FromSeconds(30));
        }
    }

    [Fact]
    public async Task APeekFailsOpenToo()
    {
        ScriptThrows(new RedisTimeoutException(CommandFlags.None, "timed out", CommandStatus.Unknown));

        var decision = await Sut(_connection).PeekAsync(
            "login-ip", "203.0.113.7", RateLimitPolicy.PerMinute(5), CancellationToken.None);

        decision.Allowed.ShouldBeTrue();
        decision.Remaining.ShouldBe(5);
    }

    // ------------------------------------------------------------------ clearing

    /// <summary>
    /// Every listed window is deleted, in one round trip, and with the keys the counters were
    /// written to. Clearing the minute of a minute-and-hour pair leaves a lockout that outlives a
    /// correct password with the minute counter visibly empty beside it.
    /// </summary>
    [Fact]
    public async Task AResetDeletesEveryListedWindowInOneRoundTrip()
    {
        await Sut(_connection).ResetAsync(
            "backoffice-sign-in",
            "alice@liontravel.com",
            [RateLimitPolicy.PerMinute(10), RateLimitPolicy.PerHour(60)],
            CancellationToken.None);

        await _database.Received(1).KeyDeleteAsync(
            Arg.Is<RedisKey[]>(keys =>
                keys.Length == 2
                && keys[0].ToString() == RedisRateLimiter.BuildKey(
                    Prefix, "backoffice-sign-in", "alice@liontravel.com", TimeSpan.FromMinutes(1))
                && keys[1].ToString() == RedisRateLimiter.BuildKey(
                    Prefix, "backoffice-sign-in", "alice@liontravel.com", TimeSpan.FromHours(1))),
            Arg.Any<CommandFlags>());
    }

    /// <summary>
    /// A reset that cannot reach Redis does not throw. It runs after the sign-in has already been
    /// decided, so turning a bookkeeping write into a 502 would fail a request that succeeded; what
    /// is lost is bounded by the window and errs towards refusing.
    /// </summary>
    [Fact]
    public async Task AFailedResetDoesNotFailTheOperationThatAskedForIt()
    {
        _database.KeyDeleteAsync(Arg.Any<RedisKey[]>(), Arg.Any<CommandFlags>())
            .Throws(new RedisTimeoutException(CommandFlags.None, "timed out", CommandStatus.Unknown));

        await Should.NotThrowAsync(() => Sut(_connection).ResetAsync(
            "backoffice-sign-in",
            "alice@liontravel.com",
            [RateLimitPolicy.PerMinute(10)],
            CancellationToken.None));
    }

    [Fact]
    public async Task AResetWithNoWindowsListedTouchesNothing()
    {
        await Sut(_connection).ResetAsync(
            "backoffice-sign-in", "alice@liontravel.com", [], CancellationToken.None);

        await _database.DidNotReceiveWithAnyArgs().KeyDeleteAsync(default(RedisKey[])!, default);
    }

    private void ScriptReturns(RedisResult reply) =>
        _database.ScriptEvaluateAsync(
                Arg.Any<string>(),
                Arg.Any<RedisKey[]>(),
                Arg.Any<RedisValue[]>(),
                Arg.Any<CommandFlags>())
            .Returns(reply);

    private void ScriptThrows(Exception cause) =>
        _database.ScriptEvaluateAsync(
                Arg.Any<string>(),
                Arg.Any<RedisKey[]>(),
                Arg.Any<RedisValue[]>(),
                Arg.Any<CommandFlags>())
            .Throws(cause);
}
