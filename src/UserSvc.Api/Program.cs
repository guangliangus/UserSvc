using Asp.Versioning;
using FluentValidation;
using Microsoft.AspNetCore.Authentication;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Scalar.AspNetCore;
using Serilog;
using UserSvc.Api.Auth;
using UserSvc.Api.Errors;
using UserSvc.Api.Filters;
using UserSvc.Api.Health;
using UserSvc.Application.Features.Profile;
using UserSvc.Application.Features.Sessions;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Security;
using UserSvc.Infrastructure;

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

// ---------------------------------------------------------------- Infrastructure (ports -> adapters)
builder.Services.AddUserSvcInfrastructure(builder.Configuration, builder.Environment.IsDevelopment());

// ---------------------------------------------------------------- Application
// Decision 05: no MediatR. App services are registered directly and injected into controllers.
builder.Services.AddScoped<ProfileAppService>();
builder.Services.AddScoped<SessionAppService>();
builder.Services.AddSingleton<IdentifierProtector>();
builder.Services.AddValidatorsFromAssemblyContaining<UpdateProfileRequestValidator>();

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUser, HttpContextCurrentUser>();

// ---------------------------------------------------------------- Authentication
if (builder.Environment.IsDevelopment())
{
    // Placeholder, Development only. Production swaps in OpenIddict issuance plus JwtBearer
    // validation (decision 10).
    builder.Services
        .AddAuthentication(DevAuthenticationHandler.SchemeName)
        .AddScheme<AuthenticationSchemeOptions, DevAuthenticationHandler>(
            DevAuthenticationHandler.SchemeName, _ => { });
}
else
{
    throw new InvalidOperationException(
        "No production authentication scheme is wired yet. Add the OpenIddict/JwtBearer adapter " +
        "before running outside Development — failing to start beats silently accepting anyone.");
}

builder.Services.AddAuthorization();

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
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<AppExceptionHandler>();

// ---------------------------------------------------------------- Three probes, three meanings
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("postgres", tags: ["ready"]);

var app = builder.Build();

app.UseExceptionHandler();
app.UseSerilogRequestLogging();

app.UseAuthentication();
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
    app.MapScalarApiReference();
}

await app.RunAsync();

/// <summary>WebApplicationFactory in the integration tests needs a visible entry point type.</summary>
public partial class Program;
