using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using UserSvc.Application.Ports.Auth;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Suppliers;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Application.Ports.TestWhitelist;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Application.Ports.Feedback;
using UserSvc.Application.Ports.Verification;
using UserSvc.Application.Features.RiskControl;
using UserSvc.Infrastructure.Auth;
using UserSvc.Infrastructure.BackOffice;
using UserSvc.Infrastructure.External;
using UserSvc.Infrastructure.Persistence;
using UserSvc.Infrastructure.Persistence.Repositories;
using UserSvc.Infrastructure.Platform;

using UserSvc.Application.Features.SocialIdentity;

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
        services.AddScoped<IUserPasskeyRepository, UserPasskeyRepository>();
        services.AddScoped<IPasskeyIdentityLink, PasskeyIdentityLink>();
        services.AddScoped<IFeedbackRepository, FeedbackRepository>();
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

        // --- Supplier mountings and the consumer test whitelist (slice 12) ---
        // One class, two ports: this slice's own read/write outlet and the narrow directory the
        // tenancy slice consults on every context resolution. Registered as the concrete type and
        // forwarded, so both ports resolve the SAME instance inside a request rather than two
        // adapters over one DbContext.
        services.AddScoped<SupplierCompanyLinkRepository>();
        services.AddScoped<ISupplierCompanyLinkRepository>(
            provider => provider.GetRequiredService<SupplierCompanyLinkRepository>());
        services.AddScoped<ITestWhitelistRepository, TestWhitelistRepository>();
        services.AddScoped<IConsumerAccountDirectory, TestWhitelistConsumerDirectory>();
        services.AddScoped<ITenantMemberRepository, TenantMemberRepository>();
        services.AddScoped<IUserTenantRoleRepository, UserTenantRoleRepository>();
        services.AddSingleton<IClock, SystemClock>();

        AddObjectStorage(services, configuration);
        AddRedis(services, configuration);
        AddPasskeys(services, configuration);
        AddSocialIdentityProviders(services, configuration);
        AddNotificationClient(services, configuration);
        AddRiskControl(services, configuration);
        AddStaffDirectory(services, configuration);
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

        // Third key space on the same multiplexer, and the only one of the three that fails
        // CLOSED - it is the sole record of whether a self-contained credential has been spent, so
        // allowing on a Redis failure would not degrade the single-use guarantee but delete it.
        // See ISingleUseMarkerStore for the full reasoning.
        services.AddSingleton<ISingleUseMarkerStore, RedisSingleUseMarkerStore>();
    }

    /// <summary>
    /// Adaptive send-code throttling and the CAPTCHA escalation (slice 05).
    /// <para>
    /// <b>Scoped, not singleton.</b> <see cref="RiskControlService"/> depends on a typed
    /// <c>HttpClient</c>, which is transient; a singleton capturing it would pin one
    /// <c>HttpMessageHandler</c> for the process lifetime and stop the factory rotating
    /// connections - the DNS-staleness bug typed clients exist to avoid.
    /// </para>
    /// <para>
    /// <b>The reCAPTCHA secret is deliberately not required at startup.</b> One endpoint out of the
    /// whole service needs it; login, registration, sessions, the back office and the send-code
    /// throttle itself all work without it. Making the host refuse to start would put the failure
    /// on a path everything crosses in order to guard one that almost nothing does - the same
    /// mistake as a placeholder that throws from a read every request makes.
    /// </para>
    /// </summary>
    private static void AddRiskControl(IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<RiskControlOptions>()
            .Bind(configuration.GetSection(RiskControlOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<RecaptchaOptions>()
            .Bind(configuration.GetSection(RecaptchaOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddHttpClient<ICaptchaVerifier, RecaptchaClient>((provider, client) =>
                client.BaseAddress = new Uri(
                    provider.GetRequiredService<IOptions<RecaptchaOptions>>().Value.BaseAddress,
                    UriKind.Absolute))
            .AddStandardResilienceHandler()
            .Configure((options, provider) =>
            {
                var recaptcha = provider.GetRequiredService<IOptions<RecaptchaOptions>>().Value;
                options.AttemptTimeout.Timeout = recaptcha.AttemptTimeout;
                options.TotalRequestTimeout.Timeout = recaptcha.TotalRequestTimeout;
                options.Retry.MaxRetryAttempts = recaptcha.MaxRetryAttempts;

                // Somebody is waiting on this call to finish signing in. Honouring a throttled
                // provider's Retry-After would park the request for as long as it asks.
                options.Retry.ShouldRetryAfterHeader = false;

                options.CircuitBreaker.SamplingDuration = MaxOf(
                    TimeSpan.FromSeconds(30), recaptcha.AttemptTimeout * 2);
            });

        services.AddScoped<IRiskControlService, RiskControlService>();
    }

    /// <summary>
    /// The corporate staff directory, behind a real client (see <see cref="LionTravelStaffDirectory"/>).
    /// <para>
    /// No <c>ValidateOnStart</c> and nothing <c>[Required]</c>: one capability needs this section,
    /// and a deployment without it must still boot and still serve every other door. The adapter
    /// checks its own configuration at the point of use and answers 500 NOT_CONFIGURED naming
    /// exactly which keys are absent.
    /// </para>
    /// </summary>
    private static void AddStaffDirectory(IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<LionTravelOptions>()
            .Bind(configuration.GetSection(LionTravelOptions.SectionName))
            .ValidateDataAnnotations();

        // Singleton: the in-process half of the application-token cache and the gate that collapses
        // concurrent mints are its state; a scoped instance would hold neither across requests.
        services.AddSingleton<LionTravelAccessTokenCache>();

        // No BaseAddress: the upstream is three hosts and the adapter builds absolute URIs.
        // Retries stay ON, unlike the WeChat clients - nothing here is a single-use credential from
        // our side, and a transient 503 means the code was never examined at all.
        services
            .AddHttpClient<IStaffDirectory, LionTravelStaffDirectory>()
            .AddStandardResilienceHandler()
            .Configure((options, provider) =>
            {
                var staff = provider.GetRequiredService<IOptions<LionTravelOptions>>().Value;

                options.AttemptTimeout.Timeout = staff.AttemptTimeout;
                options.TotalRequestTimeout.Timeout = staff.TotalRequestTimeout;
                options.Retry.ShouldRetryAfterHeader = false;
                options.CircuitBreaker.SamplingDuration = MaxOf(
                    TimeSpan.FromSeconds(30), staff.AttemptTimeout * 2);
            });

        // A factory, so the sign-in service can be constructed - and the password door served - on
        // a deployment with no staff directory configured. Injecting the client itself would make
        // one door's secrets a dependency of the other door.
        services.AddTransient<Func<IStaffDirectory>>(provider => provider.GetRequiredService<IStaffDirectory>);
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
    /// The two directories that answer "what does the platform say about this tenant". One is real
    /// now and one is not, and the asymmetry is the whole content of this method.
    /// <para>
    /// The supplier-to-company mountings live in <b>this</b> service's own table, so the second
    /// registration is the real adapter. The placeholder that answered "no mountings" to everything
    /// while the table did not exist is <b>deleted</b>, not merely unregistered: an unreferenced
    /// second implementation of a port is a class the next reader has to disprove, and two
    /// registrations for one port is how last-one-wins quietly decides what callers get.
    /// </para>
    /// <para>
    /// The company and supplier registers are somebody else's tables, so the first registration is
    /// still <see cref="UnavailableTenantMasterDataDirectory"/> - now the <b>only</b> placeholder
    /// left in the service. It answers null, which every caller reads as "not reached" and falls
    /// open on; see that class for why a throw would be the wrong shape. Replacing that <b>one</b>
    /// line is the remaining cutover.
    /// </para>
    /// </summary>
    private static void AddTenantMasterData(IServiceCollection services)
    {
        services.AddSingleton<ITenantMasterDataDirectory, UnavailableTenantMasterDataDirectory>();

        // The real adapter, and SCOPED rather than singleton: it reads the request's own DbContext,
        // and a singleton over a scoped context is the classic way to capture a disposed one. It is
        // the same instance the supplier-link endpoints resolve, so both halves of the table agree
        // about which rows count as a mounting.
        //
        // Its reads are on the shared DbContext, which is what bounds the blast radius of this
        // cutover: the tenant-context resolution that crosses it already reads that context several
        // times over, so this adds no failure source the caller did not already have. The one new
        // way to break it is deployment order - code released before db/0012 is applied answers
        // 'relation does not exist' on every company or supplier context resolution, taking the
        // whole authority face down. DDL first, then code (decision 14); that ordering is the
        // guard, and deliberately not a catch here, because swallowing that error would silently
        // narrow every scope envelope in the service instead.
        services.AddScoped<ISupplierCompanyLinkDirectory>(
            provider => provider.GetRequiredService<SupplierCompanyLinkRepository>());
    }

    private static TimeSpan MaxOf(TimeSpan left, TimeSpan right) => left > right ? left : right;

    /// <summary>
    /// Where avatars are stored. The adapter is the real Azure Blob client; what it may be missing
    /// is a connection string, and it refuses per request rather than at startup when it is - see
    /// <see cref="AzureBlobObjectStorage"/> for why one endpoint's secret must not gate the boot.
    /// <para>
    /// No <c>ValidateOnStart</c> chained onto a <c>[Required]</c> connection string, therefore, but
    /// the section is still validated: <see cref="AzureBlobOptions.Validate"/> checks the container
    /// name and, when a connection string is supplied at all, that it parses.
    /// </para>
    /// <para>
    /// Singleton: <see cref="Azure.Storage.Blobs.BlobServiceClient"/> owns a pooled HTTP pipeline
    /// and is thread-safe, so one instance serves the process. Swapping this single line for an S3
    /// adapter is the whole of a move to EKS.
    /// </para>
    /// </summary>
    private static void AddObjectStorage(IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<AzureBlobOptions>()
            .Bind(configuration.GetSection(AzureBlobOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddSingleton<IObjectStorage, AzureBlobObjectStorage>();
    }

    /// <summary>
    /// WebAuthn. Unlike its neighbours in this file there is no external dependency to configure:
    /// the FIDO2 library verifies attestations and assertions locally against the credential rows
    /// in our own table, so this adapter is complete the moment the relying-party identity is set.
    /// <para>
    /// Both registrations are singletons. <see cref="Fido2WebAuthnCeremony"/> holds one immutable
    /// <c>Fido2</c> instance built from validated options, and the flow store holds the shared
    /// multiplexer and the key prefix - neither touches the request's DbContext.
    /// </para>
    /// </summary>
    private static void AddPasskeys(IServiceCollection services, IConfiguration configuration)
    {
        // ValidateDataAnnotations, but deliberately NOT ValidateOnStart, which every other options
        // type in this file uses.
        //
        // ValidateOnStart would make an unconfigured relying-party identity refuse to boot the
        // whole service - and a passkey RP id is not something every deployment has yet. Measured
        // while writing this slice: adding it took down the integration-test host and every test
        // that starts one, none of which has anything to do with passkeys. That is the same
        // mistake as a placeholder that throws from a read every request crosses; the capability
        // that is missing here is passkeys, so passkeys are what must fail.
        //
        // Validation still happens, on the first resolution of IOptions<PasskeyOptions> - which is
        // the construction of the ceremony below, which is the first passkey request. That request
        // gets a 500 naming the missing keys; nothing else in the service notices.
        services.AddOptions<PasskeyOptions>()
            .Bind(configuration.GetSection(PasskeyOptions.SectionName))
            .ValidateDataAnnotations();

        // The ceremony state shares the multiplexer and the key prefix with the revocation set -
        // same Redis, different key space - but fails CLOSED on both read and write, where the
        // revocation set fails open on read. See RedisPasskeyFlowStore for why the direction is
        // opposite: there is no fallback underneath a challenge.
        services.AddSingleton<IPasskeyFlowStore, RedisPasskeyFlowStore>();
        services.AddSingleton<IWebAuthnCeremony, Fido2WebAuthnCeremony>();
    }

    /// <summary>
    /// The third-party identity providers: WeChat web OAuth, the WeChat mini program, Firebase and
    /// LINE.
    /// <para>
    /// <b>Every one of these is a real adapter, not a placeholder.</b> The protocols are public, so
    /// the code exists and is complete; what a deployment supplies is the credentials. The options
    /// are <c>[Required]</c> and validated on start, so a host routed at these endpoints without
    /// them refuses to boot rather than answering "invalid code" to every user - a failure that
    /// looks like the provider's fault and is not.
    /// </para>
    /// <para>
    /// <b>Retries are switched off on the two WeChat clients and left on for LINE</b>, which is the
    /// one non-obvious line in here. A WeChat authorization code and a mini-program js_code are
    /// single-use: a retry after a timeout is answered with "code already consumed", so it cannot
    /// succeed, and all it buys is a slower failure and a log line that reads like a replay attack.
    /// A LINE id_token is verifiable as many times as you like, so a transient 503 there genuinely
    /// is worth another attempt.
    /// </para>
    /// </summary>
    private static void AddSocialIdentityProviders(IServiceCollection services, IConfiguration configuration)
    {
        // ValidateDataAnnotations, but deliberately NOT ValidateOnStart on any of these.
        //
        // MEASURED, not assumed: with ValidateOnStart, a deployment that has no WeChat AppId - which
        // is every deployment today, and the integration-test host - fails to boot, and all 24
        // integration tests die at startup with a WeChat credential error. None of them has
        // anything to do with WeChat. That is the same mistake as a placeholder that throws from a
        // read every request crosses: the capability missing here is third-party sign-in, so
        // third-party sign-in is what must fail.
        //
        // Validation still happens - on the first resolution of the options, which is the first
        // request to one of these endpoints. That request gets a 500 naming the missing keys, and
        // nothing else in the service notices.
        services.AddOptions<SocialIdentityOptions>()
            .Bind(configuration.GetSection(SocialIdentityOptions.SectionName))
            .ValidateDataAnnotations();

        services.AddOptions<WechatOptions>()
            .Bind(configuration.GetSection(WechatOptions.SectionName))
            .ValidateDataAnnotations();

        services.AddOptions<WechatMiniOptions>()
            .Bind(configuration.GetSection(WechatMiniOptions.SectionName))
            .ValidateDataAnnotations();

        services.AddOptions<LineOptions>()
            .Bind(configuration.GetSection(LineOptions.SectionName))
            .ValidateDataAnnotations();

        services.AddOptions<FirebaseOptions>()
            .Bind(configuration.GetSection(FirebaseOptions.SectionName))
            .ValidateDataAnnotations();

        // Singleton: it holds the in-process half of the token cache and the semaphore that
        // collapses concurrent refreshes. A scoped instance would hold neither across requests,
        // which is the whole point of it.
        services.AddSingleton<WechatMiniAccessTokenCache>();

        // Factories, so SocialIdentityAppService does not construct all four providers to serve one.
        // Each typed client reads its own validated options when it is built, so building the lot
        // made every provider's endpoint depend on every provider's credentials.
        services.AddTransient<Func<IWechatClient>>(p => p.GetRequiredService<IWechatClient>);
        services.AddTransient<Func<IWechatMiniClient>>(p => p.GetRequiredService<IWechatMiniClient>);
        services.AddTransient<Func<ILineClient>>(p => p.GetRequiredService<ILineClient>);
        services.AddTransient<Func<IFirebaseTokenVerifier>>(p => p.GetRequiredService<IFirebaseTokenVerifier>);

        // Singleton: FirebaseApp is process-global and caches Google's public signing certificates.
        services.AddSingleton<IFirebaseTokenVerifier, FirebaseTokenVerifier>();

        services
            .AddHttpClient<IWechatClient, WechatHttpClient>((provider, client) =>
                client.BaseAddress = new Uri(
                    provider.GetRequiredService<IOptions<WechatOptions>>().Value.BaseAddress,
                    UriKind.Absolute))
            .AddStandardResilienceHandler()
            .Configure(NoRetryForSingleUseCredentials);

        services
            .AddHttpClient<IWechatMiniClient, WechatMiniHttpClient>((provider, client) =>
                client.BaseAddress = new Uri(
                    provider.GetRequiredService<IOptions<WechatMiniOptions>>().Value.BaseAddress,
                    UriKind.Absolute))
            .AddStandardResilienceHandler()
            .Configure(NoRetryForSingleUseCredentials);

        services
            .AddHttpClient<ILineClient, LineHttpClient>((provider, client) =>
                client.BaseAddress = new Uri(
                    provider.GetRequiredService<IOptions<LineOptions>>().Value.BaseAddress,
                    UriKind.Absolute))
            .AddStandardResilienceHandler()
            .Configure(options =>
            {
                options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(5);
                options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(15);
                options.Retry.MaxRetryAttempts = 2;

                // Somebody is waiting on a sign-in. Honouring a Retry-After from LINE would park
                // the request for as long as LINE asked, bounded only by the total budget.
                options.Retry.ShouldRetryAfterHeader = false;
            });
    }
    /// <summary>
    /// Timeouts and a circuit breaker, but no retries: the credential being exchanged is
    /// single-use, so a second attempt is guaranteed to be refused. See
    /// <see cref="AddSocialIdentityProviders"/>.
    /// <para>
    /// The retry strategy rejects <c>MaxRetryAttempts = 0</c> at startup, so it is disabled by
    /// telling it nothing is retryable rather than by asking for zero attempts.
    /// </para>
    /// </summary>
    private static void NoRetryForSingleUseCredentials(HttpStandardResilienceOptions options)
    {
        options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(5);
        options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(10);
        options.Retry.ShouldHandle = _ => ValueTask.FromResult(false);
    }
}
