using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;

namespace UserSvc.Api.Health;

/// <summary>
/// Wired to <c>/health/ready</c> only. <b>Never to liveness</b> — a database blip should pull
/// replicas out of the load balancer, not restart all of them. That mistake is the most common and
/// most damaging way to misconfigure the three probes.
/// <para>
/// The template's shape: <c>SELECT 1</c> over a pooled connection from the process-wide
/// <see cref="NpgsqlDataSource"/>. The previous version built a scoped <c>DbContext</c> and asked
/// <c>CanConnectAsync</c>, which constructs the EF model to answer a question the pool can answer
/// alone. A probe should cost what a probe costs.
/// </para>
/// </summary>
public sealed class DatabaseHealthCheck(NpgsqlDataSource dataSource) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await using var command = dataSource.CreateCommand("SELECT 1");
            await command.ExecuteScalarAsync(cancellationToken);
            return HealthCheckResult.Healthy();
        }
        catch (NpgsqlException ex)
        {
            return HealthCheckResult.Unhealthy("PostgreSQL connectivity check failed.", ex);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            // Npgsql surfaces its own command timeout this way; the probe's caller did not cancel.
            return HealthCheckResult.Unhealthy("PostgreSQL connectivity check timed out.", ex);
        }
    }
}
