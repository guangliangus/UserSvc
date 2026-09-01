using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using UserSvc.Application.Ports.Auth;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Infrastructure.External;
using UserSvc.Infrastructure.Persistence;
using UserSvc.Infrastructure.Persistence.Repositories;
using UserSvc.Infrastructure.Platform;

namespace UserSvc.Infrastructure;

/// <summary>
/// The single place ports are wired to adapters. Control flows from the application layer into
/// the infrastructure; the dependency points the other way, because the infrastructure implements
/// interfaces the application defines. That inversion is the whole idea (decision 03).
/// </summary>
public static class DependencyInjection
{
    public static IServiceCollection AddUserSvcInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration,
        bool isDevelopment)
    {
        var connectionString = configuration.GetConnectionString("Default")
                               ?? throw new InvalidOperationException(
                                   "ConnectionStrings:Default is required.");

        services.AddDbContext<UserSvcDbContext>(options => options
            .UseNpgsql(connectionString, npgsql => npgsql.EnableRetryOnFailure())
            .UseSnakeCaseNamingConvention());

        services.AddScoped<IUnitOfWork, UnitOfWork>();
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IUserSessionRepository, UserSessionRepository>();
        services.AddSingleton<IClock, SystemClock>();

        // --- Placeholders: when the matching slice lands, only these two lines change and no
        //     caller is touched ---

        if (!isDevelopment)
        {
            throw new InvalidOperationException(
                "ISessionRevocationStore has no production implementation yet. " +
                "The in-memory placeholder does not propagate revocations across replicas, " +
                "so it must not run outside Development. Wire the Redis adapter first.");
        }

        services.AddSingleton<ISessionRevocationStore, InMemorySessionRevocationStore>();
        services.AddSingleton<INotificationClient, UnavailableNotificationClient>();

        return services;
    }
}
