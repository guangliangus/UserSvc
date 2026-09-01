using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>
/// Hosts the real API - the real Program.cs, the real DI graph, the real middleware pipeline -
/// against the throwaway containers.
/// <para>
/// Everything is pushed in through <see cref="IWebHostBuilder.UseSetting"/> rather than an
/// in-memory configuration source, because that is the only source that reliably wins:
/// <c>DeferredHostBuilder</c> turns host settings into <c>--key=value</c> command-line arguments,
/// and <c>WebApplication.CreateBuilder(args)</c> reads those as its highest-precedence source.
/// A <c>ConfigureAppConfiguration</c> callback would be layered <i>before</i>
/// appsettings.Development.json and silently lose.
/// </para>
/// <para>
/// The content root is not set here on purpose. Microsoft.AspNetCore.Mvc.Testing emits
/// MvcTestingAppManifest.json into the test output and the factory uses it to point the content
/// root at src/UserSvc.Api, which is what makes appsettings.Development.json load. That file
/// carries IdentifierProtection:Pepper and :DataKey, both [Required] with ValidateOnStart, so
/// without it the host refuses to boot.
/// </para>
/// </summary>
internal sealed class UserSvcApplicationFactory(
    string postgresConnectionString,
    string redisConfiguration) : WebApplicationFactory<Program>
{
    /// <summary>Matches appsettings.Development.json, so the Redis keys the assertions look for are
    /// the keys the service actually writes.</summary>
    public const string RedisKeyPrefix = "usersvc:";

    /// <summary>The access-token lifetime, which doubles as the TTL of every revocation-set entry.
    /// Pinned here so a test can assert the TTL against a number it did not invent.</summary>
    public static readonly TimeSpan AccessTokenLifetime = TimeSpan.FromMinutes(10);

    /// <summary>Low enough that the device cap can be reached in three sign-ins instead of eleven.</summary>
    public const int MaxActiveDevices = 2;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // WebApplicationFactory already forces Development for a minimal-hosting entry point. It is
        // repeated here because three things depend on it - DevAuthenticationHandler being
        // registered at all, the token endpoint accepting plain HTTP, and OpenIddict falling back
        // to a development signing certificate - and a dependency that strong should be visible.
        builder.UseEnvironment(Environments.Development);

        builder.UseSetting("ConnectionStrings:Default", postgresConnectionString);
        builder.UseSetting("Redis:Configuration", redisConfiguration);
        builder.UseSetting("Redis:KeyPrefix", RedisKeyPrefix);

        builder.UseSetting("AuthSession:AccessTokenLifetime", AccessTokenLifetime.ToString("c"));
        builder.UseSetting(
            "AuthSession:MaxActiveDevices",
            MaxActiveDevices.ToString(System.Globalization.CultureInfo.InvariantCulture));

        // [Required] and validated at startup. Nothing in these tests calls the notification
        // service; an unroutable address is the honest placeholder.
        builder.UseSetting("Notification:BaseAddress", "http://127.0.0.1:1/");

        // Sign with in-memory keys. Without this the host reaches for a development certificate in
        // the CurrentUser/My store, which on macOS opens fine and then blocks the first time the
        // private key is used - the whole suite hangs inside token generation with no error to
        // read. A test host has no business asking the operating system for a key.
        builder.UseSetting("AuthToken:UseEphemeralKeys", "true");

        // The service logs one line per request plus a warning per intentionally failed one. At
        // Information that buries the assertion failures in the test output.
        builder.UseSetting("Serilog:MinimumLevel:Default", "Warning");
    }
}
