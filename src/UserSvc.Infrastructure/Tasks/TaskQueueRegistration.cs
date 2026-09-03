using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Infrastructure.Tasks;

/// <summary>
/// Wires the task-queue workers: the poll loop, the reclaim, and the handlers they dispatch to.
/// </summary>
public static class TaskQueueRegistration
{
    /// <summary>
    /// Registers the runner and the reclaim, and binds the <c>Tasks</c> section.
    /// <para>
    /// <b>Register this LAST among the host's hosted services.</b> The framework stops hosted
    /// services in reverse registration order, so last-registered is stopped - and therefore
    /// drained - first, while the rest of the host is still up. That is what the Go service's
    /// shutdown path spells out by hand: stop accepting new async work, drain it, and only then
    /// let the HTTP server and the database pool go. Registered early instead, the drain would be
    /// awaited after every other service's stop had already had its share of
    /// <c>HostOptions.ShutdownTimeout</c>.
    /// </para>
    /// <para>
    /// Both services are registered unconditionally, including when the queue is switched off.
    /// Deciding here would mean reading <c>IOptions.Value</c> while the host is being built, which
    /// is the one thing this project's guards forbid outright: a bad <c>Tasks:*</c> value would
    /// stop the host from booting instead of stopping the queue. So the switch is inside the two
    /// services, where a bad value costs the queue alone - and where a zero worker count still
    /// costs nothing at all, because both return before starting any timer or touching the
    /// database.
    /// </para>
    /// </summary>
    /// <param name="services">The container.</param>
    /// <param name="configuration">Configuration to bind <see cref="TaskQueueOptions"/> from.</param>
    /// <returns>The same collection, for chaining.</returns>
    public static IServiceCollection AddTaskQueueWorkers(
        this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // ValidateDataAnnotations but NOT ValidateOnStart: the whole section is optional, so a
        // deployment that never mentions it boots on the defaults, and a deployment that gets a
        // value wrong loses the queue rather than the service (docs/architecture.md).
        services.AddOptions<TaskQueueOptions>()
            .Bind(configuration.GetSection(TaskQueueOptions.SectionName))
            .ValidateDataAnnotations();

        // The clock both services wait on. TryAdd, because it is the framework's own abstraction
        // and something else may well register it first; TimeProvider.System is the real clock and
        // a test substitutes a manual one to drive the poll intervals without waiting for them.
        services.TryAddSingleton(TimeProvider.System);

        services.AddHostedService<TaskQueueRunner>();
        services.AddHostedService<TaskQueueReclaimer>();

        return services;
    }

    /// <summary>
    /// Registers one queue's handler.
    /// <para>
    /// The handler is scoped, because it owns its own database writes and gets a fresh scope per
    /// task. Its queue name is read off the type - <c>ITaskHandler.QueueName</c> is a static
    /// member - so the runner learns which queues exist without constructing anything, and a
    /// handler that cannot be constructed breaks its own tasks and no other queue.
    /// </para>
    /// </summary>
    /// <typeparam name="THandler">The handler to register. Exactly one per queue name; the runner
    /// refuses to poll a queue that has two, naming both.</typeparam>
    /// <param name="services">The container.</param>
    /// <returns>The same collection, for chaining.</returns>
    public static IServiceCollection AddTaskHandler<THandler>(this IServiceCollection services)
        where THandler : class, ITaskHandler
    {
        ArgumentNullException.ThrowIfNull(services);

        // A blank queue name would be enqueued by nobody and polled by nobody - a handler that
        // silently never runs. It is a programming mistake rather than a configuration one, so it
        // throws here, at registration, rather than being logged at boot.
        ArgumentException.ThrowIfNullOrWhiteSpace(THandler.QueueName);

        services.AddScoped<THandler>();
        services.AddSingleton(new TaskHandlerRegistration(THandler.QueueName, typeof(THandler)));

        return services;
    }
}
