using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Infrastructure.Tasks;

/// <summary>
/// The queue-depth signal: how many rows of one queue are claimable right now, reported on a
/// cadence from inside the poll loop that owns it.
/// <para>
/// <b>It is a log line and not a metric, because this service has no metrics pipeline.</b>
/// Decision 20 wires three signals, and today two of them exist: OpenTelemetry traces (spans, via
/// <c>AddOtlpExporter</c>) and Serilog logs. There is no <c>WithMetrics</c> and no exporter for
/// one, so a <c>Meter</c> here would publish a gauge that nothing collects - a dashboard nobody
/// can build, which is worse than a log line somebody can grep. The count is written as a
/// structured property (<c>Depth</c>), so a log-based metric picks it up unchanged, and when a
/// metrics pipeline does land this class is the single call site to change.
/// </para>
/// <para>
/// <b>Quiet at rest, loud with a backlog.</b> A gauge can be sampled every ten seconds forever;
/// a log cannot. So it reports only when there is something to say: while the depth is non-zero,
/// and once more when it returns to zero, so "the backlog cleared" is as visible as the backlog
/// was.
/// </para>
/// </summary>
internal sealed class QueueDepthSignal(TimeProvider time, ILogger logger, TimeSpan interval)
{
    private long? _reportedAt;
    private int _lastDepth;

    /// <summary>
    /// Reports the depth if the cadence has elapsed, and otherwise does nothing.
    /// </summary>
    /// <param name="scopeFactory">Scope source: <see cref="ITaskQueue"/> is scoped and this is
    /// called from a singleton.</param>
    /// <param name="queueName">The queue to measure.</param>
    /// <param name="cancellationToken">The runner's stopping token.</param>
    public async Task ReportAsync(
        IServiceScopeFactory scopeFactory, string queueName, CancellationToken cancellationToken)
    {
        // The process clock, and correctly so: this is how often to write a log line, not a
        // comparison against a stored timestamp. Every time value that decides whether a task is
        // due is PostgreSQL's now() - see ITaskQueue - and this is not one of them.
        if (_reportedAt is not null && time.GetElapsedTime(_reportedAt.Value) < interval)
        {
            return;
        }

        _reportedAt = time.GetTimestamp();

        int depth;

        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var queue = scope.ServiceProvider.GetRequiredService<ITaskQueue>();

            depth = await queue.CountPendingAsync(queueName, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Debug, not error. A failed COUNT(*) is a lost diagnostic and never a lost task, and
            // whatever broke it is about to break the claim in the same iteration - which logs an
            // error of its own. Two errors per iteration for one outage is how a log stops being
            // readable during the incident it is for.
            logger.LogDebug(ex, "Could not read the depth of queue {QueueName}.", queueName);

            return;
        }

        if (depth > 0)
        {
            logger.LogInformation(
                "Queue {QueueName} has {Depth} task(s) claimable now.", queueName, depth);
        }
        else if (_lastDepth > 0)
        {
            logger.LogInformation("Queue {QueueName} backlog is cleared.", queueName);
        }

        _lastDepth = depth;
    }
}
