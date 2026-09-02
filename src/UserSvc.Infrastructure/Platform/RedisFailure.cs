using StackExchange.Redis;

namespace UserSvc.Infrastructure.Platform;

/// <summary>
/// The one place in the service that says what a StackExchange.Redis failure looks like.
/// <para>
/// Every Redis adapter here decides its own <i>direction</i> on a store failure - the revocation
/// set's read allows and its write throws, the rate limiter allows, the single-use marker refuses,
/// the snapshot cache recomputes, readiness reports unhealthy. What none of them should own is the
/// <i>classification</i>, because that is not a policy at all: it is a fact about a third-party
/// library, it is not what the type hierarchy suggests, and it was previously restated in eight
/// files - which is exactly how six of them came to be a shape behind the other two.
/// </para>
/// <para>
/// <b>The hierarchy is not what it looks like.</b> Only <c>RedisConnectionException</c> and
/// <c>RedisServerException</c> derive from <c>RedisException</c>.
/// <c>RedisTimeoutException</c> derives from <see cref="TimeoutException"/> and
/// <c>RedisCommandException</c> derives straight from <see cref="Exception"/>, so a guard written
/// as <c>catch (RedisException)</c> misses every timeout - which is the failure a degraded path
/// exists for in the first place.
/// </para>
/// <para>
/// <b>The fourth shape is a cancelled task, and it is deliberate on the library's part.</b>
/// StackExchange.Redis 3.1.31 keeps a cached <see cref="TaskCanceledException"/> and uses it as a
/// message's terminal state: <c>Message.Cancel()</c> hands it to the message's result box, and
/// <c>TaskResultBox&lt;T&gt;</c> turns precisely that exception into <c>TrySetCanceled</c> rather
/// than <c>TrySetException</c>. So a caller awaiting the command does not get any
/// <c>Redis*Exception</c> - it gets a cancelled task, and <c>await</c> throws
/// <see cref="TaskCanceledException"/> with no inner exception and nothing in its type to say
/// Redis was involved. Four bridge sites reach that state, and three of them run <i>after</i> the
/// caller has been handed its task, so the cancellation is what the caller observes.
/// </para>
/// <para>
/// <b>Observed, not inferred.</b> Against a real Redis on the production
/// <c>ConfigurationOptions</c> - <c>AbortOnConnectFail=false</c>, 500 ms async timeout,
/// <c>BacklogPolicy.FailFast</c> - 38 of 40 concurrent <c>ScriptEvaluateAsync</c> calls threw
/// <c>System.Threading.Tasks.TaskCanceledException</c> ("A task was canceled.") when the
/// multiplexer was disposed or closed while their commands were still on the wire. That is the
/// shape of a graceful shutdown, of a rolling deployment, and of any internal teardown that
/// replaces a connection while a command is being written. An earlier attempt to reproduce it with
/// a dead endpoint could not, and the reason is in this same taxonomy: a bridge that is <i>not
/// connected</i> refuses through a different site, which throws <c>RedisConnectionException</c>
/// synchronously and discards the cancelled task. Both observations were right about different
/// paths.
/// </para>
/// <para>
/// <b>Why the token filter is not optional.</b> A cancellation that came from the caller's own
/// token is not a store failure: the client has gone away, and converting that into "Redis is
/// down" would swallow a disconnect into a degraded answer nobody reads, log noise as an outage,
/// and - in a fail-closed adapter - report a Redis fault to a caller that had already left.
/// So the caller's cancellation always propagates, and only a cancellation nobody asked for counts
/// as the store's.
/// </para>
/// </summary>
public static class RedisFailure
{
    /// <summary>
    /// Whether <paramref name="exception"/> is the store failing rather than this service's own
    /// mistake or its caller's cancellation.
    /// </summary>
    /// <param name="exception">The exception a Redis call raised.</param>
    /// <param name="cancellationToken">
    /// The token the caller passed in. Pass the real one wherever it is in scope: it is the only
    /// thing that separates "the store gave up" from "the client hung up". Where no caller token
    /// can reach the operation at all, <see cref="CancellationToken.None"/> is the honest answer,
    /// because then no cancellation observed there can be the caller's.
    /// </param>
    /// <remarks>
    /// Deliberately total and side-effect free: it runs inside <c>when</c> clauses, and an
    /// exception thrown from an exception filter is swallowed by the runtime and read as "no
    /// match", which would silently turn a handled failure into an unhandled one.
    /// </remarks>
    public static bool IsStoreFailure(Exception exception, CancellationToken cancellationToken) =>
        exception switch
        {
            RedisException or RedisTimeoutException or RedisCommandException => true,
            OperationCanceledException => !cancellationToken.IsCancellationRequested,
            _ => false,
        };
}
