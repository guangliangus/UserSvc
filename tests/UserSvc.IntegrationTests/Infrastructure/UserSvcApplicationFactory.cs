using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
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
/// <param name="postgresConnectionString">Connection string of the throwaway database.</param>
/// <param name="redisConfiguration">Configuration string of the throwaway Redis.</param>
/// <param name="overrides">
/// Extra host settings, applied <b>after</b> everything below so they win.
/// <para>
/// It exists for the tests that need a differently configured deployment rather than a different
/// request - "no back-office ticket key" being the one that matters, because a missing capability
/// is only provably isolated if a host without it still serves everything else. Overriding through
/// the same <c>UseSetting</c> channel keeps that host identical to this one in every other respect;
/// a second factory class would drift.
/// </para>
/// </param>
/// <param name="peerAddress">
/// A client address to stamp on every request, or null to leave the connection without one.
/// <para>
/// <b>Null is the default because null is what TestServer actually does</b>, and that turns out to
/// matter. <c>TestServer</c> serves requests over no socket, so
/// <c>HttpContext.Connection.RemoteIpAddress</c> is null and every per-source budget in the
/// service - which reads that address and disables itself when there is none - is silently
/// switched off for the whole suite. That is why a suite signing in twenty times cannot throttle
/// itself on the per-address dimension, and equally why nothing here can exercise that dimension
/// unless it is asked for. Setting it is opt-in, per host, so a test about the per-address lockout
/// can have one without switching the lockout on underneath every other test.
/// </para>
/// </param>
internal sealed class UserSvcApplicationFactory(
    string postgresConnectionString,
    string redisConfiguration,
    IReadOnlyDictionary<string, string>? overrides = null,
    string? peerAddress = null) : WebApplicationFactory<Program>
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

        // The back-office sign-in ticket's HMAC key, which the two back-office grants are the whole
        // of back-office authentication on top of.
        //
        // Supplied here rather than left to appsettings.Development.json, which does carry a
        // development value, because the two files answer different questions. A failing
        // back-office test then means the code is wrong, not that somebody edited a developer's
        // config file - the same reason the connection string, Redis and the notification address
        // are all stated above rather than inherited. It stays a distinct value from the
        // development one so that neither file's key can quietly become "the" key.
        //
        // It is 32 bytes of hex, which is the minimum the ticket service accepts; a shorter key is
        // not a weaker ticket but a forgeable one.
        builder.UseSetting(
            "BackOfficeSignIn:SignInTicketKey",
            "696e746567726174696f6e2d746573742d7469636b65742d6b65792d33326279");

        // The service logs one line per request plus a warning per intentionally failed one. At
        // Information that buries the assertion failures in the test output.
        builder.UseSetting("Serilog:MinimumLevel:Default", "Warning");

        // Last, so a test that asked for a differently configured deployment actually gets one.
        if (overrides is null)
        {
            return;
        }

        foreach (var (key, value) in overrides)
        {
            builder.UseSetting(key, value);
        }
    }

    /// <summary>
    /// Installs the peer-address middleware, when one was asked for.
    /// <para>
    /// Through <see cref="IStartupFilter"/> rather than a <c>ConfigureWebHost</c> callback because
    /// the address has to be in place before anything reads it, and a startup filter is the one
    /// hook that <b>prepends</b> to the pipeline the application built rather than appending to it.
    /// </para>
    /// </summary>
    protected override IHost CreateHost(IHostBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (peerAddress is { } address)
        {
            builder.ConfigureServices(services => services.AddSingleton<IStartupFilter>(
                new PeerAddressStartupFilter(IPAddress.Parse(address))));
        }

        return base.CreateHost(builder);
    }

    /// <summary>Puts a client address on the connection of every request, first in the pipeline.</summary>
    private sealed class PeerAddressStartupFilter(IPAddress address) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, following) =>
            {
                context.Connection.RemoteIpAddress = address;
                await following();
            });

            next(app);
        };
    }
}
