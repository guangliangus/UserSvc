using System.Collections.Concurrent;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;
using StackExchange.Redis;
using UserSvc.Infrastructure.External;
using UserSvc.Infrastructure.Platform;
using Xunit;

namespace UserSvc.UnitTests.External;

/// <summary>
/// The two upstream application-token caches - the corporate staff directory's and the WeChat mini
/// program's - tested side by side because they are deliberately the same class twice.
/// <para>
/// What is pinned here is that a token and the instant it stops being usable move as <b>one</b>
/// value. Held in two fields they could not: a reader outside the refresh gate could take the
/// token from one refresh and the expiry from the next, and a <see cref="DateTimeOffset"/> is
/// sixteen bytes, so a reader could see an instant that was never written at all. Neither is
/// reachable by a test on demand - that is exactly what makes the shape worth asserting rather
/// than the symptom.
/// </para>
/// <para>
/// Every case runs against both caches. The day one of them needs to fail in a different
/// direction, splitting them starts by splitting a test in here, which is the point.
/// </para>
/// </summary>
public sealed class AccessTokenCacheTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 2, 10, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// One cache behind the two members every case needs, so a test body can be written once and
    /// run against both implementations.
    /// </summary>
    private sealed record Probe(
        string Name,
        Type CacheType,
        Func<bool, Func<CancellationToken, Task<(string Token, TimeSpan Ttl)>>, DateTimeOffset, Task<string>> Get,
        Func<Task> Invalidate);

    public static TheoryData<string> CacheNames => new("liontravel", "wechat-mini");

    // ---------------------------------------------------------------- the pair moves together

    /// <summary>
    /// A refresh writes the token and its expiry as one value, so the second read is answered from
    /// the new token's own window. If the halves were swapped separately, a reader could be left
    /// holding a fresh token against the previous one's deadline - which either retires a good
    /// token early or, the direction that matters, keeps a dead one alive.
    /// </summary>
    [Theory]
    [MemberData(nameof(CacheNames))]
    public async Task ARefreshedTokenIsUsableForItsOwnLifetimeAndNotTheOldOnes(string name)
    {
        var probe = ProbeFor(name);
        var minted = 0;

        Task<(string Token, TimeSpan Ttl)> Mint(CancellationToken _)
        {
            var n = Interlocked.Increment(ref minted);
            return Task.FromResult(($"token-{n}", TimeSpan.FromSeconds(60)));
        }

        (await probe.Get(false, Mint, Now)).ShouldBe("token-1");

        // Inside the first token's window: no second mint.
        (await probe.Get(false, Mint, Now.AddSeconds(30))).ShouldBe("token-1");
        minted.ShouldBe(1);

        // Past it: a second mint, whose own 60 seconds start now.
        (await probe.Get(false, Mint, Now.AddSeconds(61))).ShouldBe("token-2");

        // The read that proves the pair moved together. The second token's window ends at
        // 121 seconds; a stale expiry left over from the first would have ended it at 60 and this
        // read would mint a third time.
        (await probe.Get(false, Mint, Now.AddSeconds(90))).ShouldBe("token-2");
        minted.ShouldBe(2);
    }

    /// <summary>
    /// An invalidation drops both halves at once. Dropping only the token would leave a live
    /// expiry behind - harmless - while dropping only the expiry would leave a token the upstream
    /// has already rejected reachable for as long as its window lasted.
    /// </summary>
    [Theory]
    [MemberData(nameof(CacheNames))]
    public async Task AnInvalidationDropsTheTokenAndItsWindowTogether(string name)
    {
        var probe = ProbeFor(name);
        var minted = 0;

        Task<(string Token, TimeSpan Ttl)> Mint(CancellationToken _)
        {
            var n = Interlocked.Increment(ref minted);
            return Task.FromResult(($"token-{n}", TimeSpan.FromMinutes(30)));
        }

        (await probe.Get(false, Mint, Now)).ShouldBe("token-1");

        await probe.Invalidate();

        // Well inside the first token's half hour, and it is gone anyway.
        (await probe.Get(false, Mint, Now.AddMinutes(1))).ShouldBe("token-2");
        minted.ShouldBe(2);
    }

    /// <summary>
    /// Fifty simultaneous cold-start callers produce one mint and one answer. The gate is what
    /// collapses them; this asserts the re-check inside it actually sees the winner's write.
    /// </summary>
    [Theory]
    [MemberData(nameof(CacheNames))]
    public async Task ConcurrentColdStartCallersCollapseIntoOneMint(string name)
    {
        var probe = ProbeFor(name);
        var minted = 0;

        async Task<(string Token, TimeSpan Ttl)> Mint(CancellationToken _)
        {
            var n = Interlocked.Increment(ref minted);

            // Long enough that the queue behind the gate is real rather than theoretical.
            await Task.Delay(20).ConfigureAwait(false);

            return ($"token-{n}", TimeSpan.FromMinutes(30));
        }

        var answers = await Task.WhenAll(
            Enumerable.Range(0, 50).Select(_ => Task.Run(() => probe.Get(false, Mint, Now))));

        minted.ShouldBe(1);
        answers.Distinct(StringComparer.Ordinal).ShouldHaveSingleItem().ShouldBe("token-1");
    }

    /// <summary>
    /// Readers and invalidations at the same time. Not a proof - a torn read is a race and races
    /// do not appear on demand - but it is the shape that produced one: every answer here has to
    /// be a token some mint actually produced, never the empty string a half-written state would
    /// read as and never an instant nobody wrote.
    /// </summary>
    [Theory]
    [MemberData(nameof(CacheNames))]
    public async Task ReadsRunningAlongsideInvalidationsOnlyEverSeeAWholeToken(string name)
    {
        var probe = ProbeFor(name);
        var minted = new ConcurrentDictionary<string, byte>(StringComparer.Ordinal);
        var counter = 0;

        Task<(string Token, TimeSpan Ttl)> Mint(CancellationToken _)
        {
            var token = $"token-{Interlocked.Increment(ref counter)}";
            minted[token] = 0;

            return Task.FromResult((token, TimeSpan.FromMinutes(30)));
        }

        var observed = new ConcurrentBag<string>();

        var readers = Enumerable.Range(0, 32).Select(_ => Task.Run(async () =>
        {
            for (var i = 0; i < 40; i++)
            {
                observed.Add(await probe.Get(false, Mint, Now));
            }
        }));

        var invalidators = Enumerable.Range(0, 4).Select(_ => Task.Run(async () =>
        {
            for (var i = 0; i < 40; i++)
            {
                await probe.Invalidate();
            }
        }));

        await Task.WhenAll(readers.Concat(invalidators));

        observed.ShouldNotBeEmpty();
        observed.ShouldAllBe(token => token.Length > 0);
        observed.ShouldAllBe(token => minted.ContainsKey(token));
    }

    // ---------------------------------------------------------------- the shape that makes it so

    /// <summary>
    /// The structural half, and the reason the cases above stay true under load nobody can
    /// reproduce: the mutable state is <b>one</b> reference field, so a refresh is a single
    /// assignment and a reader sees the state entirely before or entirely after it. A
    /// <see cref="DateTimeOffset"/> field would reintroduce a value nobody can read atomically;
    /// a second mutable field would reintroduce the pair that can be read out of step.
    /// </summary>
    [Theory]
    [MemberData(nameof(CacheNames))]
    public void TheMutableStateIsOneReferenceFieldRatherThanAPairOfFields(string name)
    {
        var fields = ProbeFor(name).CacheType
            .GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)

            // The primary constructor's captured parameters are emitted as fields whose names are
            // not valid identifiers; they are the injected dependencies, not cache state.
            .Where(field => !field.Name.StartsWith('<'))
            .ToList();

        fields.ShouldNotContain(field => field.FieldType == typeof(DateTimeOffset));

        var mutable = fields.Where(field => !field.IsInitOnly).ToList();

        mutable.ShouldHaveSingleItem();
        mutable[0].FieldType.IsValueType.ShouldBeFalse();
    }

    // ---------------------------------------------------------------- probes

    private static Probe ProbeFor(string name) => name switch
    {
        "liontravel" => LionTravelProbe(),
        "wechat-mini" => WechatMiniProbe(),
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, "No such cache."),
    };

    private static Probe LionTravelProbe()
    {
        var cache = new LionTravelAccessTokenCache(
            ConnectionWithNoSharedToken(),
            Options.Create(new RedisOptions { Configuration = "localhost:6379", KeyPrefix = "test:" }),
            NullLogger<LionTravelAccessTokenCache>.Instance);

        return new Probe(
            "liontravel",
            typeof(LionTravelAccessTokenCache),
            (force, mint, now) => cache.GetAsync(force, mint, now, CancellationToken.None),
            cache.InvalidateAsync);
    }

    private static Probe WechatMiniProbe()
    {
        var cache = new WechatMiniAccessTokenCache(
            ConnectionWithNoSharedToken(),
            Options.Create(new RedisOptions { Configuration = "localhost:6379", KeyPrefix = "test:" }),
            NullLogger<WechatMiniAccessTokenCache>.Instance);

        return new Probe(
            "wechat-mini",
            typeof(WechatMiniAccessTokenCache),
            (force, fetch, now) => cache.GetAsync(force, fetch, now, CancellationToken.None),
            cache.InvalidateAsync);
    }

    /// <summary>
    /// A Redis that answers every read as a miss, so what is under test is the in-process half.
    /// The shared layer has its own TTL and its own tests; here it would answer for windows the
    /// local half has correctly let go of.
    /// </summary>
    private static IConnectionMultiplexer ConnectionWithNoSharedToken()
    {
        var database = Substitute.For<IDatabase>();
        database.StringGetAsync(Arg.Any<RedisKey>(), Arg.Any<CommandFlags>()).Returns(RedisValue.Null);

        var connection = Substitute.For<IConnectionMultiplexer>();
        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object>()).Returns(database);

        return connection;
    }
}
