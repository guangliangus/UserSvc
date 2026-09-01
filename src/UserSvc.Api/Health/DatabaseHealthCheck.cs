using System.Data.Common;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using UserSvc.Infrastructure.Persistence;

namespace UserSvc.Api.Health;

/// <summary>
/// Wired to <c>/health/ready</c> only. <b>Never to liveness</b> — a database blip should pull
/// replicas out of the load balancer, not restart all of them. That mistake is the most common and
/// most damaging way to misconfigure the three probes.
/// </summary>
public sealed class DatabaseHealthCheck(UserSvcDbContext db) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            return await db.Database.CanConnectAsync(cancellationToken)
                ? HealthCheckResult.Healthy()
                : HealthCheckResult.Unhealthy("PostgreSQL is not reachable.");
        }
        catch (InvalidOperationException ex)
        {
            return HealthCheckResult.Unhealthy("PostgreSQL connectivity check failed.", ex);
        }
        catch (DbException ex)
        {
            return HealthCheckResult.Unhealthy("PostgreSQL connectivity check failed.", ex);
        }
    }
}
