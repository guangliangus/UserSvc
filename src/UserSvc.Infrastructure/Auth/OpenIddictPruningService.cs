using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace UserSvc.Infrastructure.Auth;

/// <summary>
/// Deletes expired and long-since-revoked OpenIddict tokens and authorizations.
/// <para>
/// <b>This physically deletes rows, which the house rule forbids</b> — and does so on purpose. The
/// rule exists so business history survives; these are protocol artefacts with no history value,
/// and OpenIddict writes two token rows per token request, so at a ten-minute access-token lifetime
/// an unpruned store grows by roughly a hundred rows per device per day and never stops. Do not
/// file this as a violation; do keep the retention window long enough that an incident
/// investigation still finds the rows it needs.
/// </para>
/// <para>
/// The managers are registered <b>scoped</b>, so this singleton creates a scope per tick. Resolving
/// them from the root provider instead throws at startup under scope validation — which is the
/// good outcome; the bad one is a captive DbContext shared across every tick.
/// </para>
/// </summary>
public sealed class OpenIddictPruningService(
    IServiceScopeFactory scopeFactory,
    IOptions<OpenIddictPruningOptions> options,
    ILogger<OpenIddictPruningService> logger) : BackgroundService
{
    private readonly OpenIddictPruningOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(_options.Interval);

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await PruneAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                // A failed prune is a capacity problem, never a correctness one: the next tick
                // retries. Letting it escape would take the whole host down with it.
                logger.LogError(ex, "OpenIddict pruning failed; retrying on the next tick.");
            }
        }
    }

    private async Task PruneAsync(CancellationToken cancellationToken)
    {
        var threshold = DateTimeOffset.UtcNow - _options.Retention;

        await using var scope = scopeFactory.CreateAsyncScope();

        var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var prunedTokens = await tokens.PruneAsync(threshold, cancellationToken);

        // Authorizations go second: OpenIddict refuses to prune one that still has tokens hanging
        // off it, so pruning them in the other order clears almost nothing on the first pass.
        var authorizations = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
        var prunedAuthorizations = await authorizations.PruneAsync(threshold, cancellationToken);

        logger.LogInformation(
            "Pruned {TokenCount} OpenIddict tokens and {AuthorizationCount} authorizations older than {Threshold:o}.",
            prunedTokens, prunedAuthorizations, threshold);
    }
}

/// <summary>
/// How aggressively the OpenIddict store is pruned. Bound and validated by the API host, because
/// that is where the rest of the OpenIddict runtime configuration lives (decision 10).
/// </summary>
public sealed class OpenIddictPruningOptions
{
    public const string SectionName = "OpenIddictPruning";

    /// <summary>How often the job runs. Frequent enough that a burst never accumulates, rare enough
    /// that the DELETE never competes with the token endpoint.</summary>
    [Range(typeof(TimeSpan), "00:05:00", "24:00:00")]
    public TimeSpan Interval { get; init; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long an expired or revoked row is kept before deletion. It must comfortably outlast the
    /// refresh-token lifetime, or the job deletes chains that are still in use; it is also the
    /// window an incident investigation has to work with.
    /// </summary>
    [Range(typeof(TimeSpan), "1.00:00:00", "365.00:00:00")]
    public TimeSpan Retention { get; init; } = TimeSpan.FromDays(45);
}
