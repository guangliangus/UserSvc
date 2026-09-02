using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using StackExchange.Redis;
using UserSvc.Application.Errors;
using UserSvc.Infrastructure.Platform;
using Xunit;

namespace UserSvc.UnitTests.Platform;

/// <summary>
/// The consume-once marker: the command it issues, and the direction it fails in.
/// <para>
/// Both matter for the same reason. The command has to be one atomic conditional write, because a
/// check followed by a write would tell two concurrent redemptions of one credential that both had
/// claimed it - the replay this store exists to stop, only harder to reproduce. And the failure
/// direction has to be closed, against the grain of every other Redis adapter in this service,
/// because there is nothing else that knows whether a credential has been spent.
/// </para>
/// </summary>
public sealed class RedisSingleUseMarkerStoreTests
{
    private const string Prefix = "usersvc:";

    private readonly IDatabase _database = Substitute.For<IDatabase>();
    private readonly IConnectionMultiplexer _connection = Substitute.For<IConnectionMultiplexer>();

    public RedisSingleUseMarkerStoreTests() =>
        _connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(_database);

    private RedisSingleUseMarkerStore Sut() => new(
        _connection,
        Options.Create(new RedisOptions { Configuration = "localhost:6379", KeyPrefix = Prefix }),
        NullLogger<RedisSingleUseMarkerStore>.Instance);

    /// <summary>
    /// <c>SET key 1 PX ttl NX</c>, and nothing else. <c>When.NotExists</c> is the atomicity: with
    /// <c>When.Always</c> every redemption would claim successfully and the marker would record
    /// nothing at all. The expiry is what keeps the key space bounded, so it must travel on the
    /// same command rather than as a second one that a dropped connection could lose.
    /// </summary>
    [Fact]
    public async Task AClaimIsOneConditionalWriteCarryingItsOwnExpiry()
    {
        Claims(true);

        var claimed = await Sut().TryClaimAsync(
            "back-office-sign-in-ticket", "abc123", TimeSpan.FromMinutes(3), CancellationToken.None);

        claimed.ShouldBeTrue();

        await _database.Received(1).StringSetAsync(
            "usersvc:consumed:back-office-sign-in-ticket:abc123",
            Arg.Any<RedisValue>(),
            TimeSpan.FromMinutes(3),
            false,
            When.NotExists,
            CommandFlags.None);
    }

    /// <summary>An id already in the store is not claimed again, which is what a replay looks
    /// like from here.</summary>
    [Fact]
    public async Task AnAlreadyClaimedIdIsRefused()
    {
        Claims(false);

        (await Sut().TryClaimAsync(
                "back-office-sign-in-ticket", "abc123", TimeSpan.FromMinutes(3), CancellationToken.None))
            .ShouldBeFalse();
    }

    /// <summary>
    /// Two purposes never share a key space, so an id that collides across two kinds of credential
    /// cannot consume the other one.
    /// </summary>
    [Fact]
    public async Task TwoPurposesNeverShareAKey()
    {
        Claims(true);

        var sut = Sut();
        await sut.TryClaimAsync("purpose-a", "same-id", TimeSpan.FromMinutes(1), CancellationToken.None);
        await sut.TryClaimAsync("purpose-b", "same-id", TimeSpan.FromMinutes(1), CancellationToken.None);

        await _database.Received(1).StringSetAsync(
            "usersvc:consumed:purpose-a:same-id",
            Arg.Any<RedisValue>(),
            Arg.Any<TimeSpan?>(),
            Arg.Any<bool>(),
            Arg.Any<When>(),
            Arg.Any<CommandFlags>());

        await _database.Received(1).StringSetAsync(
            "usersvc:consumed:purpose-b:same-id",
            Arg.Any<RedisValue>(),
            Arg.Any<TimeSpan?>(),
            Arg.Any<bool>(),
            Arg.Any<When>(),
            Arg.Any<CommandFlags>());
    }

    /// <summary>
    /// <b>The fail-closed case.</b> Every other Redis adapter here allows on a failure; this one
    /// refuses, because a fail-open answer would silently make every intercepted credential
    /// replayable again for the duration of a blip and nothing in the response or the trail would
    /// say the guarantee had lapsed.
    /// </summary>
    [Theory]
    [InlineData("connection")]
    [InlineData("timeout")]
    [InlineData("command")]
    [InlineData("cancellation")]
    public async Task AnUnreachableStoreRefusesRatherThanAllowing(string failure)
    {
        _database.StringSetAsync(
                Arg.Any<RedisKey>(),
                Arg.Any<RedisValue>(),
                Arg.Any<TimeSpan?>(),
                Arg.Any<bool>(),
                Arg.Any<When>(),
                Arg.Any<CommandFlags>())
            .Throws(Failure(failure));

        var refusal = await Should.ThrowAsync<UpstreamException>(() => Sut().TryClaimAsync(
            "back-office-sign-in-ticket", "abc123", TimeSpan.FromMinutes(3), CancellationToken.None));

        // 502 and not 401: nothing here is evidence that the credential was replayed, and telling
        // an operator it was would send them hunting for a stolen ticket during a Redis outage.
        refusal.StatusCode.ShouldBe(502);
        refusal.ErrorCode.ShouldBe(ErrorCodes.UpstreamUnavailable);
        refusal.InnerException.ShouldNotBeNull();
    }

    /// <summary>
    /// A caller's own cancellation is theirs, not a store failure - it must not be dressed up as an
    /// upstream fault.
    /// </summary>
    [Fact]
    public async Task ACancellationTheCallerAskedForIsNotAStoreFailure()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Should.ThrowAsync<OperationCanceledException>(() => Sut().TryClaimAsync(
            "back-office-sign-in-ticket", "abc123", TimeSpan.FromMinutes(3), cancelled.Token));

        await _database.DidNotReceiveWithAnyArgs().StringSetAsync(
            default, default, default, default, default, default);
    }

    /// <summary>
    /// A non-positive expiry is refused as the argument error it is. Redis rejects the command
    /// outright, which the caller would read as "the store is unreachable" and answer 502 for -
    /// and a caller that passed zero thinking it meant "no expiry" would be writing an immortal
    /// key per credential into a store nothing ever prunes.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public async Task ANonPositiveTimeToLiveIsRefusedAsAnArgumentError(int seconds)
    {
        await Should.ThrowAsync<ArgumentOutOfRangeException>(() => Sut().TryClaimAsync(
            "back-office-sign-in-ticket",
            "abc123",
            TimeSpan.FromSeconds(seconds),
            CancellationToken.None));

        await _database.DidNotReceiveWithAnyArgs().StringSetAsync(
            default, default, default, default, default, default);
    }

    private void Claims(bool result) =>
        _database.StringSetAsync(
                Arg.Any<RedisKey>(),
                Arg.Any<RedisValue>(),
                Arg.Any<TimeSpan?>(),
                Arg.Any<bool>(),
                Arg.Any<When>(),
                Arg.Any<CommandFlags>())
            .Returns(result);

    /// <summary>
    /// The four shapes, spelled out because three of them are not what the names suggest:
    /// <c>RedisTimeoutException</c> derives from <see cref="TimeoutException"/>,
    /// <c>RedisCommandException</c> straight from <see cref="Exception"/>, and a fresh multiplexer's
    /// first command can surface a plain <see cref="TaskCanceledException"/>.
    /// </summary>
    private static Exception Failure(string kind) => kind switch
    {
        "connection" => new RedisConnectionException(
            ConnectionFailureType.SocketFailure, CommandFlags.None, "down", null, CommandStatus.Unknown),
        "timeout" => new RedisTimeoutException(CommandFlags.None, "timed out", CommandStatus.Unknown),
        "command" => new RedisCommandException("bad command"),
        _ => new TaskCanceledException("A task was canceled."),
    };
}
