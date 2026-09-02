using Microsoft.Extensions.Diagnostics.HealthChecks;
using StackExchange.Redis;
using UserSvc.Infrastructure.Platform;

namespace UserSvc.Api.Health;

/// <summary>
/// Wired to <c>/health/ready</c> only. <b>Never to liveness</b> — a Redis blip should pull replicas
/// out of the load balancer, not restart all of them. That mistake is the most common and most
/// damaging way to misconfigure the three probes.
/// <para>
/// Hand-written rather than <c>AspNetCore.HealthChecks.Redis</c>: its latest stable release (9.0.0)
/// targets net8.0 and pins Microsoft.Extensions.Diagnostics.HealthChecks 8.0.11 <b>and
/// StackExchange.Redis 2.7.4</b>. The second one is the deal-breaker — this solution is on
/// StackExchange.Redis 3.x, and taking a major-version downgrade for eleven lines of code is not a
/// trade worth making.
/// </para>
/// <para>
/// Note the deliberate inconsistency with <c>RedisSessionRevocationStore</c>: the store fails
/// open on a Redis fault because it is an optional extra check, whereas readiness reports the fault
/// honestly. Something has to tell the operator Redis is gone, and this is it.
/// </para>
/// </summary>
public sealed class RedisHealthCheck(IConnectionMultiplexer connection) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // PingAsync takes no CancellationToken; the configured AsyncTimeout is what bounds it.
            var latency = await connection.GetDatabase().PingAsync();
            return HealthCheckResult.Healthy($"Redis responded in {latency.TotalMilliseconds:F0} ms.");
        }
        // Readiness reports unhealthy; what COUNTS as a Redis failure is RedisFailure's to say, for
        // all eight adapters. An unclassified shape here would leave the probe throwing instead of
        // answering, and a readiness endpoint that throws is indistinguishable from one that is
        // simply down - which is the one thing a probe exists to tell apart.
        catch (Exception ex) when (RedisFailure.IsStoreFailure(ex, cancellationToken))
        {
            return HealthCheckResult.Unhealthy("Redis connectivity check failed.", ex);
        }
    }
}
