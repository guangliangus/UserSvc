using System.Diagnostics;
using Asp.Versioning;
using Microsoft.AspNetCore.OpenApi;
using FluentValidation;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using UserSvc.Api.Auth;
using UserSvc.Api.Errors;
using UserSvc.Api.Middleware;
using UserSvc.Api.Filters;
using UserSvc.Api.Health;
using UserSvc.Api.OpenApi;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Auth.TokenValidation;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Features.BackOffice.Consumers;
using UserSvc.Application.Features.BackOffice.SignIn;
using UserSvc.Application.Features.BackOffice.Suppliers;
using UserSvc.Application.Features.BackOffice.TestWhitelist;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Features.Account;
using UserSvc.Application.Features.Feedback;
using UserSvc.Application.Features.Passkeys;
using UserSvc.Application.Features.Profile;
using UserSvc.Application.Features.RiskControl;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Features.Sessions;
using UserSvc.Application.Features.Verification;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Security;
using UserSvc.Infrastructure;
using UserSvc.Infrastructure.Tasks;

// FluentValidation localizes its built-in messages from the ambient thread culture, so on a server
// whose locale is not English a missing field comes back described in that language - the API's
// error contract would then depend on which machine answered. Turning the language manager off
// pins the built-in messages to English; rules with an explicit WithMessage are unaffected.
// The source-language guard cannot catch this one: the text comes from a package's resources at
// run time, not from any .cs file. It was found by reading a real 400 response.
ValidatorOptions.Global.LanguageManager.Enabled = false;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------- Observability (decision 20)
// Three signals with distinct jobs, stitched together by one traceId: metrics say something is
// wrong, traces say which hop, logs say what happened on this specific request.
builder.Host.UseSerilog((context, logger) => logger
    .ReadFrom.Configuration(context.Configuration)
    .Enrich.FromLogContext());

builder.Services.AddOpenTelemetry()
    .ConfigureResource(resource => resource.AddService("user-svc"))
    .WithTracing(tracing => tracing
        .AddAspNetCoreInstrumentation()
        .AddHttpClientInstrumentation()
        .AddOtlpExporter());

// ---------------------------------------------------------------- Configuration
// Every strongly typed Options object is validated at startup: a bad value or a missing required
// setting refuses to boot rather than running degraded.
builder.Services.AddOptions<IdentifierProtectionOptions>()
    .Bind(builder.Configuration.GetSection(IdentifierProtectionOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddOptions<AuthSessionOptions>()
    .Bind(builder.Configuration.GetSection(AuthSessionOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddOptions<VerificationOptions>()
    .Bind(builder.Configuration.GetSection(VerificationOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// No ValidateDataAnnotations: every setting in this section has a working default, and the one
// that does not - BackOffice:LoginUrl - is deliberately optional. A deployment with no back office
// in front of it should boot; what it loses is credential mail, and the sender says so in its log
// rather than refusing to start the whole service.
builder.Services.AddOptions<BackOfficeAccountOptions>()
    .Bind(builder.Configuration.GetSection(BackOfficeAccountOptions.SectionName));

// Bound, and deliberately WITHOUT ValidateOnStart: the one value with no working default -
// BackOfficeSignIn:SignInTicketKey - is checked at the point of use, so a deployment with no back
// office refuses the two sign-in endpoints and boots everything else. ValidateDataAnnotations
// stays, because the ranges below it are read only on those same paths: a bad lifetime fails
// back-office sign-in and nothing that consumer sign-in, sessions or the device grant depend on.
// Without this Bind the section is unreachable - IOptions hands out the defaults, SignInTicketKey
// is empty, and every back-office sign-in answers 500 NOT_CONFIGURED no matter what the
// environment supplies.
builder.Services.AddOptions<BackOfficeSignInOptions>()
    .Bind(builder.Configuration.GetSection(BackOfficeSignInOptions.SectionName))
    .ValidateDataAnnotations();

// The same lesson as the block above, found the same way - by setting the value and watching
// nothing happen. Without this Bind, IOptions<RequestContextOptions> hands out a default-
// constructed instance forever: RequireDeviceHeadersFor is permanently empty, so the header gate
// cannot be switched on by any configuration a deployment supplies, and the paragraph on that
// property promising "set it to ["/api/v1"] and the Go behaviour is back" is not true of any
// deployment. No ValidateOnStart and no DataAnnotations, exactly as that type documents: every
// setting has a working default, and the middleware degrades to them on its own if the section
// will not bind.
builder.Services.AddOptions<RequestContextOptions>()
    .Bind(builder.Configuration.GetSection(RequestContextOptions.SectionName));

// ---------------------------------------------------------------- Infrastructure (ports -> adapters)
builder.Services.AddUserSvcInfrastructure(builder.Configuration);

// ---------------------------------------------------------------- Application
// Decision 05: no MediatR. App services are registered directly and injected into controllers.
builder.Services.AddScoped<ProfileAppService>();
builder.Services.AddScoped<SessionAppService>();
builder.Services.AddScoped<VerificationAppService>();
builder.Services.AddScoped<CaptchaAppService>();
builder.Services.AddScoped<PasskeyAppService>();
builder.Services.AddScoped<SocialIdentityAppService>();
builder.Services.AddScoped<AvatarAppService>();
builder.Services.AddScoped<FeedbackAppService>();
builder.Services.AddScoped<AccountAppService>();
builder.Services.AddScoped<TokenValidationAppService>();

// Back-office sign-in. The ticket service is a singleton holding only the options accessor and the
// clock, and it reads the signing key at the point of use rather than at construction - so an
// unconfigured deployment fails on a sign-in request, not on container build.
builder.Services.AddSingleton<BackOfficeSignInTicketService>();
builder.Services.AddScoped<BackOfficeStaffOnboarding>();
builder.Services.AddScoped<BackOfficeSignInAppService>();
builder.Services.AddScoped<BackOfficeTokenIssuer>();

// Slice 12: supplier mountings, the consumer test whitelist and the consumer lookup behind it. The
// summary service is shared by the last two - one answer to "how much of a consumer may an operator
// see" - so it is registered once rather than constructed twice.
builder.Services.AddScoped<SupplierLinkAppService>();
builder.Services.AddScoped<ConsumerSummaryService>();
builder.Services.AddScoped<ConsumerLookupAppService>();
builder.Services.AddScoped<TestWhitelistAppService>();

// The factory beside it, because TokenValidationAppService takes a Func<TestWhitelistAppService>
// rather than the service itself - docs/architecture.md, "inject Func<T> not T when a client's
// construction could fail", so that a whitelist whose own configuration is missing breaks the
// whitelist and not every token validation. Without this line the container refuses to build at
// all: ValidateOnBuild cannot resolve the Func, so the host never starts and every integration
// test dies in the factory rather than in an assertion.
builder.Services.AddTransient<Func<TestWhitelistAppService>>(
    provider => provider.GetRequiredService<TestWhitelistAppService>);

builder.Services.AddSingleton<OAuthStateService>();
builder.Services.AddSingleton<SocialBindingTokenService>();
builder.Services.AddScoped<RegistrationAppService>();

// --- Back office -----------------------------------------------------------------------------
// Registered as one block because they are one graph: the RBAC services depend on each other and
// on the cross-slice adapters in UserSvc.Infrastructure, and the container validates the whole
// thing at Build(). Registering an app service whose adapters are missing does not merely leave
// that endpoint broken - ValidateOnBuild refuses to construct the container at all, and the host
// never starts. Anything added here needs its ports wired first.
builder.Services.AddScoped<BackOfficeAccountAppService>();
builder.Services.AddScoped<BackOfficeResetTargetGate>();
builder.Services.AddScoped<BackOfficeSuperAdminAppService>();

builder.Services.AddScoped<ActiveUserRoleReader>();
builder.Services.AddScoped<AdminScopeService>();
builder.Services.AddScoped<IamAuditWriter>();
builder.Services.AddScoped<MenuAppService>();
builder.Services.AddScoped<PermissionCatalogAppService>();
builder.Services.AddScoped<RoleAppService>();
builder.Services.AddScoped<RoleDelegationService>();
builder.Services.AddScoped<RoleGrantsAppService>();
builder.Services.AddScoped<RoleVisibilityService>();
builder.Services.AddScoped<ScopeEnvelopeService>();
builder.Services.AddScoped<SuperAdminAppService>();
builder.Services.AddScoped<UserVisibilityService>();

builder.Services.AddScoped<BackOfficeContextAppService>();
builder.Services.AddScoped<TenantContextAppService>();
builder.Services.AddScoped<TenantMemberAppService>();
// Stateless and thread-safe; the Argon2 parameters are compile-time constants, so one instance
// serves every request.
builder.Services.AddSingleton<PasswordHasher>();
builder.Services.AddSingleton<IdentifierProtector>();

// The factory beside it, for IdentifierProtectionHealthCheck. HealthCheckService constructs a check
// OUTSIDE the try/catch that guards CheckHealthAsync, so a check taking the protector directly would
// turn a construction failure into an unhandled 500 on /health/ready rather than an unhealthy
// result - which is the failure that check exists to close. The protector's constructor is total
// today; this keeps the probe honest if it ever stops being (docs/architecture.md, "inject Func<T>
// not T when a client's construction could fail").
builder.Services.AddTransient<Func<IdentifierProtector>>(
    provider => provider.GetRequiredService<IdentifierProtector>);

builder.Services.AddValidatorsFromAssemblyContaining<UpdateProfileRequestValidator>();

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUser, HttpContextCurrentUser>();

// The back office's own caller. Identity comes from the validated token; authority is whatever
// BackOfficeAuthzMiddleware resolved for this request, and an empty face when it resolved nothing.
builder.Services.AddScoped<IBackOfficeCaller, HttpContextBackOfficeCaller>();

// ---------------------------------------------------------------- Authentication (decision 10)
// OpenIddict issues the tokens and validates them in the same process. Under Development a policy
// scheme still falls back to DevAuthenticationHandler when no Authorization header is present, so
// the existing curl and integration-test workflow keeps working.
builder.Services.AddUserSvcAuthentication(builder.Configuration, builder.Environment.IsDevelopment());

builder.Services.AddAuthorization(options => options.AddBackOfficePolicies());

// ---------------------------------------------------------------- HTTP
builder.Services.AddControllers(options => options.Filters.Add<ValidationFilter>());

builder.Services
    .AddApiVersioning(options =>
    {
        options.DefaultApiVersion = new ApiVersion(1, 0);
        options.ReportApiVersions = true;
        // Decision 08: the version is read from the URL segment only, never a header or query
        // string, so the gateway can route by path and version usage is visible in the logs.
        options.ApiVersionReader = new UrlSegmentApiVersionReader();
    })
    .AddMvc()
    .AddApiExplorer(options =>
    {
        options.GroupNameFormat = "'v'VVV";
        options.SubstituteApiVersionInUrl = true;
    })
    .AddOpenApi();

// One OpenAPI document per identity plane, on top of the one-per-version the versioning package
// already produces. The admin console and the mobile app then each generate a client from a file
// that holds only their own endpoints, so neither can call the other's by accident and neither has
// to read past 30 irrelevant paths. The version documents keep their names ('v1'); the back-office
// ones are 'back-office-v1'. A new API version needs a line here beside its own [ApiVersion].
// AV0029 fires because the versioning package owns document registration when
// AddApiVersioning().AddOpenApi() is used, and calling the framework's AddOpenApi beside it is
// usually a sign the two were wired twice. Here it is deliberate and additive: this registers one
// EXTRA document that is not a version at all, and the version documents keep coming from the
// package untouched. Suppressed at the single line rather than in the project file, so a second
// call somewhere else still gets caught.
#pragma warning disable AV0029
builder.Services.AddOpenApi(ApiPlanes.BackOfficeDocument("v1"));
#pragma warning restore AV0029

// ConfigureAll rather than named calls: the version document names come from the API versions the
// explorer discovers at run time, so there is no name to write here - a transformer registered
// against only the names that exist today would silently stop covering v2 on the day it appears.
builder.Services.ConfigureAll<OpenApiOptions>(options =>
{
    options.AddOperationTransformer<RequestHeadersOperationTransformer>();
    options.AddDocumentTransformer<BearerSecuritySchemeTransformer>();
    options.AddOperationTransformer<BearerSecurityOperationTransformer>();

    if (ApiPlanes.IsBackOfficeDocument(options.DocumentName, out var versionGroup))
    {
        // Self-contained rather than composed: the versioning package configures its own filter by
        // matching the document name against a version group, and 'back-office-v1' is not one, so
        // there is nothing here to compose with. The version is read off the path instead - the
        // same string, written there by SubstituteApiVersionInUrl.
        options.ShouldInclude = description =>
            (ApiPlanes.IsBackOffice(description) && ApiPlanes.VersionGroup(description) == versionGroup)
            || ApiPlanes.IsShared(description);

        return;
    }

    // A version document: keep whatever the versioning package decided about which version this
    // route belongs to, and drop the back-office plane on top of it. Replacing the delegate rather
    // than composing would put every version's endpoints into every version's document.
    var versioned = options.ShouldInclude;

    options.ShouldInclude = description =>
        (versioned is null || versioned(description)) && !ApiPlanes.IsBackOffice(description);
});

// Decision 09: RFC 9457 is the only error contract. There is no envelope.
// This callback is the last thing to touch the body on every path - the ones AppExceptionHandler
// maps and the ones it never sees, such as an authentication challenge a middleware answers by
// setting a status code and returning - which is why both members are filled here and nowhere else.
builder.Services.AddProblemDetails(options => options.CustomizeProblemDetails = context =>
{
    context.ProblemDetails.Extensions.TryAdd("errorCode", ErrorCodeFor(context.HttpContext.Response.StatusCode));

    // Assigned rather than TryAdd'd, and deliberately the bare 32-hex trace id. ASP.NET Core's own
    // ProblemDetails writers stamp traceId with Activity.Current.Id - the entire
    // "00-<trace>-<span>-01" traceparent - before this callback runs, so a TryAdd is silently
    // dropped and the published contract becomes a string no trace backend's search box accepts.
    // The bare id is also exactly what Serilog writes as {TraceId}, which is what lets one value
    // off a support ticket both grep the logs and open the trace.
    context.ProblemDetails.Extensions["traceId"] =
        Activity.Current?.TraceId.ToString() ?? context.HttpContext.TraceIdentifier;

    context.ProblemDetails.Instance ??= context.HttpContext.Request.Path;

    // Last, because it reads the errorCode filled above. This is the whole seam the i18n catalogue
    // plugs into: one call here translates the user-facing 'detail' of every failure - including the
    // 401s and 403s a middleware answers without ever reaching AppExceptionHandler - and not one
    // throw site changed to make it happen. 'title' is deliberately left alone so dashboards can
    // keep aggregating on it.
    ProblemDetailLocalization.Apply(context);
});
builder.Services.AddExceptionHandler<AppExceptionHandler>();

// ---------------------------------------------------------------- Three probes, three meanings
// Every check here is tagged "ready" and nothing is tagged for liveness, which is the whole design:
// readiness answers "should traffic be routed to me" and may fail on anything that makes an answer
// wrong, while liveness answers "is this process wedged, should I be restarted" and must fail on
// nothing a restart cannot repair. A dependency outage and a malformed secret are both in the
// second category - restarting the pod fixes neither, and a liveness check that failed on either
// would turn one of them into a cluster-wide restart storm.
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("postgres", tags: ["ready"])
    .AddCheck<RedisHealthCheck>("redis", tags: ["ready"])
    .AddCheck<IdentifierProtectionHealthCheck>("identifier-protection", tags: ["ready"]);

// ---------------------------------------------------------------- Async work (db/0014_task_queues.sql)
// The generic task queue's runner and reclaim. LAST among the hosted-service registrations, and the
// position is the whole shutdown design.
//
// The framework cancels every hosted service's stoppingToken BEFORE it awaits any of their
// StopAsync, so "stop accepting new async work" happens for all of them at once - and then it
// awaits StopAsync in REVERSE registration order, so these two, registered last, are drained
// first. Registered inside AddUserSvcInfrastructure they would sit ahead of the two OpenIddict
// services (OpenIddictRegistration.cs) and be drained after them, which is the wrong way round:
// the queue is the only hosted service here whose stop has real work to wait for.
//
// The bound on that drain is deliberately NOT HostOptions.ShutdownTimeout. That one - 30 seconds,
// the framework's default, left alone - bounds the whole shutdown, and Kestrel's own request drain
// is inside it, so lowering it to the Go service's 5s APP_SHUTDOWN_TIMEOUT would shorten HTTP
// draining on every rolling update to buy the queue nothing. Tasks:DrainTimeout carries that 5s
// instead, bounding only the queue's share; overrunning it leaves the rows claimed for the reclaim
// rather than taking the host's budget.
builder.Services.AddTaskQueueWorkers(builder.Configuration);

var app = builder.Build();

// Outermost on purpose, ahead of the exception handler. Registered after it, this middleware sees
// the exception still in flight and records the request as a 500 - so a plain validation failure,
// which the handler is about to turn into a 400, lands in the request log as a server error. Every
// SLO dashboard built on that log would then read our own 4xx as our own outage (decision 20).
// Out here it observes the status the client actually received. The exception itself is not lost:
// AppExceptionHandler logs it, at a level chosen from the mapped status.
app.UseSerilogRequestLogging();

app.UseExceptionHandler();

// An authentication challenge never reaches AppExceptionHandler - the auth handler just sets 401
// and returns, leaving an empty body with no content type. Without this, "every failure is
// ProblemDetails" is false for exactly the two statuses clients hit most often, 401 and 403.
// With AddProblemDetails registered, this middleware fills any empty error response with one.
app.UseStatusCodePages();

// Both of these only read the request and register response callbacks, so neither can swallow an
// exception: they belong INSIDE the exception handler and the status-code pages, whose bodies then
// get to read the negotiated locale and the trace id. And both must run BEFORE authentication,
// because a 401 challenge writes its body on the way back out - run them after and the one response
// class that most needs a translated sentence is the one that cannot have one.
// Neither reads sid or act, so neither belongs in the gap between authentication and authorization:
// that gap is load-bearing for RevokedSessionMiddleware and BackOfficeAuthzMiddleware, in that order.
app.UseMiddleware<TraceHeaderMiddleware>();
app.UseMiddleware<RequestContextMiddleware>();

app.UseAuthentication();

// Between authentication and authorization: there is no sid before the first, and a revoked
// session must not reach a policy that might approve it.
app.UseMiddleware<RevokedSessionMiddleware>();

// After the revocation check - a dead session must not have an authority face computed for it -
// and before authorization, because the permission gates read that face. It never fails a request:
// an unresolvable face is an empty one, which fails the gates closed and leaves the ungated
// endpoints working.
app.UseMiddleware<BackOfficeAuthzMiddleware>();

app.UseAuthorization();

app.MapControllers();

// startup and live self-check only and never aggregate external dependencies — otherwise a
// database blip triggers a restart storm across every replica.
//
// The predicates are only half of what keeps liveness answering 200. The other half is that nothing
// the pipeline resolves per request may throw for a configuration reason: with a three-byte
// IdentifierProtection:DataKey this host used to answer 500 to all three probes, because
// BackOfficeAuthzMiddleware resolves the authorization snapshot provider on every request and that
// graph reached IdentifierProtector's throwing constructor. An empty check list cannot save a probe
// from the middleware in front of it, so both halves are load-bearing.
//
// The response writer is what makes the readiness failure diagnosable: the default one answers with
// the single word "Unhealthy", which tells whoever is looking that something is wrong and nothing
// about what.
app.MapHealthChecks("/health/startup", new()
{
    Predicate = _ => false,
    ResponseWriter = HealthReportWriter.WriteAsync,
});

app.MapHealthChecks("/health/live", new()
{
    Predicate = _ => false,
    ResponseWriter = HealthReportWriter.WriteAsync,
});

app.MapHealthChecks("/health/ready", new()
{
    Predicate = check => check.Tags.Contains("ready"),
    ResponseWriter = HealthReportWriter.WriteAsync,
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi().WithDocumentPerVersion();

    // Only the UI half of Swashbuckle is referenced. Its generator (AddSwaggerGen) stays out on
    // purpose: it would describe the same controllers a second time, configured separately from
    // Microsoft.AspNetCore.OpenApi above, and the two descriptions would drift. SwaggerUI is a
    // standalone package - it wants nothing but the URL of a document someone else produced.
    app.UseSwaggerUI(options =>
    {
        // Driven off the versions the API explorer actually found, so a future v2 appears in the
        // picker on its own. GroupName is the same "v1" MapOpenApi publishes the document under:
        // both read the 'v'VVV format configured on AddApiExplorer.
        foreach (var description in app.DescribeApiVersions().OrderBy(d => d.GroupName, StringComparer.Ordinal))
        {
            var label = description.IsDeprecated
                ? description.GroupName + " (deprecated)"
                : description.GroupName;

            // Two entries per version, one per identity plane. Named rather than numbered because
            // the picker is the one place a reader chooses which surface they are looking at, and
            // "v1" twice would make that choice invisible.
            options.SwaggerEndpoint($"/openapi/{description.GroupName}.json", $"Consumer API {label}");
            options.SwaggerEndpoint(
                $"/openapi/{ApiPlanes.BackOfficeDocument(description.GroupName)}.json",
                $"Back office API {label}");
        }
    });
}

await app.RunAsync();

static string ErrorCodeFor(int statusCode) => statusCode switch
{
    StatusCodes.Status401Unauthorized => ErrorCodes.Unauthorized,
    StatusCodes.Status403Forbidden => ErrorCodes.Forbidden,
    StatusCodes.Status404NotFound => ErrorCodes.NotFound,
    StatusCodes.Status429TooManyRequests => ErrorCodes.RateLimitExceeded,
    >= 500 => ErrorCodes.InternalError,
    _ => ErrorCodes.BadRequest,
};

/// <summary>WebApplicationFactory in the integration tests needs a visible entry point type.</summary>
public partial class Program;
