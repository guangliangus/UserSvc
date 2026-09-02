using System.Diagnostics;
using Asp.Versioning;
using FluentValidation;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using UserSvc.Api.Auth;
using UserSvc.Api.Errors;
using UserSvc.Api.Middleware;
using UserSvc.Api.Filters;
using UserSvc.Api.Health;
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
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("postgres", tags: ["ready"])
    .AddCheck<RedisHealthCheck>("redis", tags: ["ready"]);

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
app.MapHealthChecks("/health/startup", new() { Predicate = _ => false });
app.MapHealthChecks("/health/live", new() { Predicate = _ => false });
app.MapHealthChecks("/health/ready", new() { Predicate = check => check.Tags.Contains("ready") });

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

            options.SwaggerEndpoint($"/openapi/{description.GroupName}.json", label);
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
