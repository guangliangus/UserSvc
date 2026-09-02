using System.Globalization;
using NSubstitute;
using StackExchange.Redis;

namespace UserSvc.UnitTests.RiskControl;

/// <summary>
/// An in-memory stand-in for the one Redis the risk engine and the rate limiter share.
/// <para>
/// It is a real store rather than a pile of stubbed return values because two of the behaviours
/// under test are relationships between operations, not single calls: redeeming a token has to
/// delete the counter keys the <i>limiter</i> wrote, and the token itself has to be consumable
/// exactly once even when ten callers try at the same moment. Neither can be observed against a
/// substitute that answers each call in isolation.
/// </para>
/// <para>
/// The script handler reproduces the compare-and-delete Lua exactly, and everything is under one
/// lock, which is what lets the concurrency test mean something: the fake is at least as atomic as
/// Redis, so a failure there is a defect in the caller and not in the double.
/// </para>
/// </summary>
internal sealed class FakeRedis
{
    private readonly Lock _gate = new();

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    public FakeRedis()
    {
        Database = Substitute.For<IDatabase>();
        Connection = Substitute.For<IConnectionMultiplexer>();
        Connection.GetDatabase(Arg.Any<int>(), Arg.Any<object>()).Returns(Database);

        Database.StringGetAsync(Arg.Any<RedisKey>(), Arg.Any<CommandFlags>())
            .Returns(call => Task.FromResult(Read(call.ArgAt<RedisKey>(0))));

        Database.KeyExistsAsync(Arg.Any<RedisKey>(), Arg.Any<CommandFlags>())
            .Returns(call => Task.FromResult(!Read(call.ArgAt<RedisKey>(0)).IsNull));

        Database.StringSetAsync(
                Arg.Any<RedisKey>(),
                Arg.Any<RedisValue>(),
                Arg.Any<TimeSpan?>(),
                Arg.Any<bool>(),
                Arg.Any<When>(),
                Arg.Any<CommandFlags>())
            .Returns(call => Task.FromResult(Write(
                call.ArgAt<RedisKey>(0),
                call.ArgAt<RedisValue>(1),
                call.ArgAt<TimeSpan?>(2))));

        Database.KeyDeleteAsync(Arg.Any<RedisKey>(), Arg.Any<CommandFlags>())
            .Returns(call => Task.FromResult(Delete(call.ArgAt<RedisKey>(0))));

        Database.ScriptEvaluateAsync(
                Arg.Any<string>(),
                Arg.Any<RedisKey[]>(),
                Arg.Any<RedisValue[]>(),
                Arg.Any<CommandFlags>())
            .Returns(call => Task.FromResult(CompareAndDelete(
                call.ArgAt<RedisKey[]>(1),
                call.ArgAt<RedisValue[]>(2))));
    }

    public IConnectionMultiplexer Connection { get; }

    public IDatabase Database { get; }

    /// <summary>Every read answers as though the connection had dropped.</summary>
    public bool FaultReads { get; set; }

    /// <summary>Every write answers as though the connection had dropped.</summary>
    public bool FaultWrites { get; set; }

    /// <summary>The compare-and-delete script answers as though the connection had dropped.</summary>
    public bool FaultScripts { get; set; }

    /// <summary>Reads a value without going through the substitute, for assertions.</summary>
    public string? Peek(string key)
    {
        lock (_gate)
        {
            return _entries.TryGetValue(key, out var entry) ? entry.Value : null;
        }
    }

    /// <summary>The TTL the value was written with, for assertions.</summary>
    public TimeSpan? TimeToLive(string key)
    {
        lock (_gate)
        {
            return _entries.TryGetValue(key, out var entry) ? entry.TimeToLive : null;
        }
    }

    public IReadOnlyList<string> Keys()
    {
        lock (_gate)
        {
            return [.. _entries.Keys];
        }
    }

    public void Set(string key, string value, TimeSpan? timeToLive = null)
    {
        lock (_gate)
        {
            _entries[key] = new Entry(value, timeToLive);
        }
    }

    /// <summary>The counter primitive the fake limiter counts with, so its keys live in the same
    /// store the risk service deletes from.</summary>
    public long Increment(string key, TimeSpan timeToLive)
    {
        lock (_gate)
        {
            var next = _entries.TryGetValue(key, out var entry)
                ? long.Parse(entry.Value, CultureInfo.InvariantCulture) + 1
                : 1;

            _entries[key] = new Entry(next.ToString(CultureInfo.InvariantCulture), timeToLive);
            return next;
        }
    }

    private RedisValue Read(RedisKey key)
    {
        if (FaultReads)
        {
            throw Dropped();
        }

        lock (_gate)
        {
            return _entries.TryGetValue(key.ToString(), out var entry) ? entry.Value : RedisValue.Null;
        }
    }

    private bool Write(RedisKey key, RedisValue value, TimeSpan? expiry)
    {
        if (FaultWrites)
        {
            throw Dropped();
        }

        lock (_gate)
        {
            _entries[key.ToString()] = new Entry(value.ToString(), expiry);
            return true;
        }
    }

    private bool Delete(RedisKey key)
    {
        if (FaultWrites)
        {
            throw Dropped();
        }

        lock (_gate)
        {
            return _entries.Remove(key.ToString());
        }
    }

    private RedisResult CompareAndDelete(RedisKey[] keys, RedisValue[] values)
    {
        if (FaultScripts)
        {
            throw Dropped();
        }

        lock (_gate)
        {
            var key = keys[0].ToString();

            if (!_entries.TryGetValue(key, out var entry))
            {
                return RedisResult.Create((RedisValue)0L);
            }

            if (!string.Equals(entry.Value, values[0].ToString(), StringComparison.Ordinal))
            {
                return RedisResult.Create((RedisValue)0L);
            }

            _entries.Remove(key);
            return RedisResult.Create((RedisValue)1L);
        }
    }

    /// <summary>
    /// A timeout rather than a connection failure on purpose: <c>RedisTimeoutException</c> derives
    /// from <see cref="TimeoutException"/> and not from <c>RedisException</c>, so it is the failure
    /// a guard written as <c>catch (RedisException)</c> silently misses. Faulting with the easy one
    /// would let exactly that bug through.
    /// </summary>
    private static RedisTimeoutException Dropped() =>
        new(CommandFlags.None, "The fake Redis is unavailable for this test.", CommandStatus.Unknown);

    private sealed record Entry(string Value, TimeSpan? TimeToLive);
}
