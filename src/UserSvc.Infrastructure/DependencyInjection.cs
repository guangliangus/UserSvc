using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using UserSvc.Application.Ports.Auth;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Application.Ports.Verification;
using UserSvc.Infrastructure.Auth;
using UserSvc.Infrastructure.BackOffice;
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
        IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("Default")
                               ?? throw new InvalidOperationException(
                                   "ConnectionStrings:Default is required.");

        services.AddSingleton<DomainEventOutboxInterceptor>();

        services.AddDbContext<UserSvcDbContext>((provider, options) => options
            .UseNpgsql(connectionString, npgsql => npgsql.EnableRetryOnFailure())
            .UseSnakeCaseNamingConvention()
            .AddInterceptors(provider.GetRequiredService<DomainEventOutboxInterceptor>()));

        // Decision 10: OpenIddict's core services and its EF stores share UserSvcDbContext, so token
        // rows commit in the same transaction as the session row they belong to. The server and
        // validation halves are registered by the API host - two AddOpenIddict() calls from two
        // assemblies compose into one configuration.
        services.AddOpenIddict()
            .AddCore(options => options
                .UseEntityFrameworkCore()
                .UseDbContext<UserSvcDbContext>()
                .ReplaceDefaultEntities<Guid>());

        services.AddScoped<ITokenChainRevoker, OpenIddictTokenChainRevoker>();

        services.AddScoped<IUnitOfWork, UnitOfWork>();
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IUserIdentityRepository, UserIdentityRepository>();
        services.AddScoped<IUserSessionRepository, UserSessionRepository>();
        services.AddScoped<IVerificationCodeRepository, VerificationCodeRepository>();
        services.AddScoped<IVerificationTicketConsumer, VerificationCodeRepository>();

        // --- Back-office (schema "iam") ---
        services.AddScoped<IBackendUserRepository, BackendUserRepository>();
        services.AddScoped<IBackendIdentityRepository, BackendIdentityRepository>();
        services.AddScoped<IRoleRepository, RoleRepository>();
        services.AddScoped<IPermissionRepository, PermissionRepository>();
        services.AddScoped<IMenuRepository, MenuRepository>();
        services.AddScoped<IRoleMenuRepository, RoleMenuRepository>();
        services.AddScoped<IRolePermissionRepository, RolePermissionRepository>();
        services.AddScoped<IIamAuditLogRepository, IamAuditLogRepository>();
        services.AddScoped<ITenantMemberRepository, TenantMemberRepository>();
        services.AddScoped<IUserTenantRoleRepository, UserTenantRoleRepository>();
        services.AddSingleton<IClock, SystemClock>();

        AddRedis(services, configuration);
        AddNotificationClient(services, configuration);
        AddRiskControl(services);
        AddStaffDirectory(services);
        AddCrossSliceDirectories(services);
        AddTenantMasterData(services);

        return services;
    }

    /// <summary>
    /// The session revocation set (decision 11). One multiplexer for the process: it is a
    /// connection pool with its own reconnect loop, not a connection, so a scoped or transient
    /// registration would build a new pool per request.
    /// </summary>
    private static void AddRedis(IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<RedisOptions>()
            .Bind(configuration.GetSection(RedisOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddSingleton<IConnectionMultiplexer>(provider => ConnectionMultiplexer.Connect(
            provider.GetRequiredService<IOptions<RedisOptions>>().Value.ToConfigurationOptions()));

        services.AddSingleton<ISessionRevocationStore, RedisSessionRevocationStore>();

        // Shares the multiplexer and the key prefix with the revocation set: same Redis, different
        // key space, opposite failure direction on write (fail-open - see RedisRateLimiter).
        services.AddSingleton<IRateLimiter, RedisRateLimiter>();
    }

    /// <summary>
    /// Risk control ships as a port with a refusing placeholder until a CAPTCHA provider is
    /// configured (see <see cref="PlaceholderRiskControlService"/>). Replacing this one line with
    /// the real adapter is the whole cutover - no calling code changes.
    /// </summary>
    private static void AddRiskControl(IServiceCollection services)
    {
        services.AddSingleton<IRiskControlService, PlaceholderRiskControlService>();
    }

    /// <summary>
    /// The corporate staff directory ships as a port with a refusing placeholder until an adapter
    /// for the real upstream exists (see <see cref="UnavailableStaffDirectory"/>). Replacing this
    /// one line with the real adapter is the whole cutover - no calling code changes.
    /// </summary>
    private static void AddStaffDirectory(IServiceCollection services)
    {
        services.AddSingleton<IStaffDirectory, UnavailableStaffDirectory>();
    }

    /// <summary>
    /// The notification capability service (decision 01) over HTTP, wrapped in the standard
    /// resilience pipeline. Order, outermost first: rate limiter, total-request timeout, retry,
    /// circuit breaker, per-attempt timeout.
    /// </summary>
    private static void AddNotificationClient(IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<NotificationOptions>()
            .Bind(configuration.GetSection(NotificationOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        // AddHttpClient<TClient, TImpl> names the client after TClient, so the client name is
        // "INotificationClient" and its resilience options instance is "INotificationClient-standard".
        // It also registers INotificationClient as transient, which is why the placeholder
        // AddSingleton<INotificationClient, UnavailableNotificationClient>() had to go: two
        // registrations for one port means last-one-wins decides what callers actually get.
        var notificationClient = services.AddHttpClient<INotificationClient, NotificationHttpClient>(
            (provider, client) =>
            {
                var options = provider.GetRequiredService<IOptions<NotificationOptions>>().Value;
                client.BaseAddress = new Uri(options.BaseAddress, UriKind.Absolute);

                // Deliberately no client.Timeout. The resilience handler sets it to
                // Timeout.InfiniteTimeSpan itself and owns the timeout budget; anything set here
                // is overwritten, so writing it would only mislead the next reader.
            });

        // OPEN QUESTION: we cannot see whether the notification service requires a service token.
        // If it does, the answer is a DelegatingHandler added here, on the IHttpClientBuilder -
        //     notificationClient.AddHttpMessageHandler<NotificationAuthHandler>();
        // - and it must be registered BEFORE the resilience handler so a 401 refresh happens once
        // per attempt rather than once per pipeline. That is also why the builder is kept in a
        // local: AddStandardResilienceHandler returns IHttpStandardResiliencePipelineBuilder, not
        // IHttpClientBuilder, so nothing can be chained onto it.
        notificationClient
            .AddStandardResilienceHandler()
            .Configure((options, provider) =>
            {
                var notification = provider.GetRequiredService<IOptions<NotificationOptions>>().Value;

                options.AttemptTimeout.Timeout = notification.AttemptTimeout;
                options.TotalRequestTimeout.Timeout = notification.TotalRequestTimeout;
                options.Retry.MaxRetryAttempts = notification.MaxRetryAttempts;

                // Send is user-facing: someone is waiting on a verification code. Retry.MaxDelay
                // does not cap a Retry-After delay - ShouldRetryAfterHeader installs a delay
                // generator that ignores it - so a throttled notification service could park the
                // request for its whole Retry-After, bounded only by the total timeout. Honouring
                // that header is right for a background sender and wrong here.
                options.Retry.ShouldRetryAfterHeader = false;

                // A startup validator demands SamplingDuration >= 2 x AttemptTimeout. Deriving it
                // instead of hard-coding 30s means lowering AttemptTimeout in one environment
                // cannot make the service refuse to boot.
                options.CircuitBreaker.SamplingDuration = MaxOf(
                    TimeSpan.FromSeconds(30),
                    notification.AttemptTimeout * 2);
            });
    }

    /// <summary>
    /// The seams between the three back-office slices.
    /// <para>
    /// Each of these ports is one slice's narrow view of a neighbour's data, declared as a port
    /// because the two were written by people who could not see each other. None of them is an
    /// external dependency, and every adapter below is a projection over a repository or a service
    /// that already exists in this process - which is why they are registered here beside the
    /// repositories rather than in the placeholder helpers further down.
    /// </para>
    /// </summary>
    private static void AddCrossSliceDirectories(IServiceCollection services)
    {
        // Read-only projections of the RBAC catalogue and the membership table.
        services.AddScoped<IRoleDirectory, RoleDirectory>();
        services.AddScoped<IRbacCatalog, RbacCatalog>();
        services.AddScoped<ITenantMemberDirectory, TenantMemberDirectory>();
        services.AddScoped<IBackOfficeUserDirectory, BackOfficeUserDirectory>();
        services.AddScoped<IBackOfficeAccountDirectory, BackOfficeAccountDirectory>();

        // Write seams. Each runs inside a transaction its caller opened.
        services.AddScoped<IBackOfficeUserProvisioner, BackOfficeUserProvisioner>();
        services.AddScoped<IGlobalAccessMemberships, GlobalAccessMemberships>();
        services.AddScoped<IIamAuditLog, IamAuditLogWriter>();

        // Standing and delegation, re-read from the database on every call.
        services.AddScoped<IAdminStandingService, AdminStandingService>();
        services.AddScoped<IRoleDelegationService, RoleDelegationDirectory>();

        // The authority snapshot and the two ports that retire it. The cache is a singleton because
        // it holds nothing but the multiplexer and the key prefix; everything that computes into it
        // is scoped, because it reads the request's own DbContext.
        services.AddSingleton<RedisAuthzSnapshotCache>();
        services.AddScoped<IAuthzSnapshotProvider, AuthzSnapshotProvider>();
        services.AddScoped<IAuthzConvergence, AuthzConvergence>();
        services.AddSingleton<ITokenVersionCache, AuthzSnapshotTokenVersionCache>();

        // Credential mail goes out through the notification client the rest of the service already
        // uses - see NotificationCredentialEmailSender for why there is no second path out.
        services.AddScoped<ICredentialEmailSender, NotificationCredentialEmailSender>();
    }

    /// <summary>
    /// The two directories that read master data owned by another service. Both ship as refusing
    /// placeholders - see <see cref="UnavailableTenantMasterDataDirectory"/> and
    /// <see cref="UnavailableSupplierCompanyLinkDirectory"/> for what each refusal costs and why
    /// the two refuse in different shapes. Replacing these two lines is the whole cutover.
    /// </summary>
    private static void AddTenantMasterData(IServiceCollection services)
    {
        services.AddSingleton<ITenantMasterDataDirectory, UnavailableTenantMasterDataDirectory>();
        services.AddSingleton<ISupplierCompanyLinkDirectory, UnavailableSupplierCompanyLinkDirectory>();
    }

    private static TimeSpan MaxOf(TimeSpan left, TimeSpan right) => left > right ? left : right;
}
