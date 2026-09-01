using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using UserSvc.Api.Controllers;
using UserSvc.Application.Features.Sessions;
using UserSvc.Infrastructure.Auth;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace UserSvc.Api.Auth;

/// <summary>
/// Wires OpenIddict as both the token issuer and the token validator for this host (decision 10).
/// <para>
/// The core services and the Entity Framework stores are registered in
/// <c>UserSvc.Infrastructure.DependencyInjection</c>; the server and validation halves live here,
/// because they are host concerns and depend on ASP.NET Core. Two <c>AddOpenIddict()</c> calls from
/// two assemblies compose into one configuration, which is exactly what makes that split legal.
/// </para>
/// </summary>
public static class OpenIddictRegistration
{
    /// <summary>Everything authentication: options, the OpenIddict server and validation stacks, the
    /// schemes, the first-party client seed and the store pruning job.</summary>
    public static IServiceCollection AddUserSvcAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<AuthTokenOptions>()
            .Bind(configuration.GetSection(AuthTokenOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<OpenIddictPruningOptions>()
            .Bind(configuration.GetSection(OpenIddictPruningOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        // The builder callbacks below run at registration time, before the options pipeline exists,
        // so the few values they need are read straight from configuration. Everything that can wait
        // until the container is built is configured through IOptions instead.
        var tokenOptions = configuration.GetSection(AuthTokenOptions.SectionName).Get<AuthTokenOptions>()
                           ?? new AuthTokenOptions();

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.SetTokenEndpointUris(TokenController.TokenEndpointPath);

                options.AllowRefreshTokenFlow();
                options.AllowCustomFlow(tokenOptions.DeviceGrantType);
                options.RegisterScopes(Scopes.OfflineAccess);

                // ---------------------------------------------------------------------------------
                // The single most important line in this file. The DEFAULT leeway is 30 seconds, and
                // within it OpenIddict ACCEPTS a replayed refresh token and mints a fresh pair -
                // silently, with a 200. Zero is what makes replaying a redeemed token answer 400
                // invalid_grant and take the whole authorization's token rows down with it, which is
                // the security promise the blueprint makes. Deleting this line does not break a test;
                // it makes the promise quietly false.
                options.SetRefreshTokenReuseLeeway(TimeSpan.Zero);

                // Deliberately NOT called: DisableAuthorizationStorage(). Chain revocation keys on
                // the authorization id, and without the store every token row carries a null one -
                // replay detection then degrades to something with no observable effect.

                // Deliberately NOT called: EnableTokenEntryValidation() on the validation side. It
                // makes every authenticated request read a token row from PostgreSQL to buy a
                // guarantee the sid claim plus the Redis revocation set already give (decision 11).

                // The access token becomes a plain RS256 JWT with typ=at+jwt so downstream services
                // can validate it as an ordinary bearer token. The refresh token stays an encrypted
                // JWE regardless - there is no switch for that one, and it needs none: only this
                // service ever reads it.
                options.DisableAccessTokenEncryption();

                if (!string.IsNullOrWhiteSpace(tokenOptions.Issuer))
                {
                    options.SetIssuer(tokenOptions.Issuer);
                }

                ConfigureCredentials(options, tokenOptions, isDevelopment);

                options.AddEventHandler(RefreshTokenReplayHandler.Descriptor);

                var aspNetCore = options.UseAspNetCore().EnableTokenEndpointPassthrough();

                if (isDevelopment)
                {
                    // Inside the Development branch and nowhere else: outside it, this would let the
                    // token endpoint hand out credentials over plain HTTP.
                    aspNetCore.DisableTransportSecurityRequirement();
                }
            })
            .AddValidation(options =>
            {
                // In-process: the validation stack reads the server's own signing keys and options
                // directly, so there is no discovery request and no key cache to go stale.
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        // Token lifetimes are not duplicated here. AuthSessionOptions.AccessTokenLifetime is also the
        // TTL of the Redis revocation entries (decision 11); if the two ever disagreed, revoked
        // access tokens would come back to life for the difference.
        services.AddOptions<OpenIddictServerOptions>()
            .Configure<IOptions<AuthSessionOptions>>((server, session) =>
            {
                server.AccessTokenLifetime = session.Value.AccessTokenLifetime;
                server.RefreshTokenLifetime = session.Value.RefreshTokenLifetime;
            });

        services.AddHostedService<FirstPartyClientSeeder>();
        services.AddHostedService<OpenIddictPruningService>();

        ConfigureSchemes(services, isDevelopment);

        return services;
    }

    /// <summary>
    /// Development keeps the header-based placeholder working, so the existing curl workflow and the
    /// integration tests are unaffected, while real tokens are validated on the same host: a policy
    /// scheme picks per request, by whether an <c>Authorization: Bearer</c> header is present.
    /// Outside Development there is one scheme and it validates properly signed tokens.
    /// </summary>
    private static void ConfigureSchemes(IServiceCollection services, bool isDevelopment)
    {
        if (!isDevelopment)
        {
            services.AddAuthentication(AuthenticationSchemes.Bearer);
            return;
        }

        services
            .AddAuthentication(AuthenticationSchemes.DevelopmentPolicy)
            .AddPolicyScheme(
                AuthenticationSchemes.DevelopmentPolicy,
                displayName: AuthenticationSchemes.DevelopmentPolicy,
                configureOptions: options => options.ForwardDefaultSelector = context =>
                    context.Request.Headers.Authorization.Count > 0
                        ? AuthenticationSchemes.Bearer
                        : AuthenticationSchemes.DevHeader)
            .AddScheme<AuthenticationSchemeOptions, DevAuthenticationHandler>(
                AuthenticationSchemes.DevHeader, _ => { });
    }

    /// <summary>
    /// Signing and encryption material.
    /// <para>
    /// Real certificates are addressed by thumbprint out of the CurrentUser/My store, so nothing
    /// here loads a PFX from disk — <c>new X509Certificate2(path, password)</c> is obsolete and a
    /// build error in this repository anyway.
    /// </para>
    /// <para>
    /// Without them, Development falls back to OpenIddict's self-signed development certificates,
    /// and to purely in-memory keys when even that is impossible: <c>AddDevelopment*Certificate</c>
    /// persists into the CurrentUser X.509 store, which needs a writable user profile and typically
    /// fails in a container — and the integration tests host the app in exactly that situation.
    /// </para>
    /// </summary>
    private static void ConfigureCredentials(
        OpenIddictServerBuilder options,
        AuthTokenOptions tokenOptions,
        bool isDevelopment)
    {
        var signing = tokenOptions.SigningCertificateThumbprint;
        var encryption = tokenOptions.EncryptionCertificateThumbprint;

        if (!string.IsNullOrWhiteSpace(signing) && !string.IsNullOrWhiteSpace(encryption))
        {
            options.AddSigningCertificate(signing);
            options.AddEncryptionCertificate(encryption);
            return;
        }

        if (!isDevelopment)
        {
            // Same discipline as the other unfinished adapters: refuse to boot rather than sign
            // production tokens with a key that disappears on the next restart and that the replica
            // next door has never seen.
            throw new InvalidOperationException(
                $"{AuthTokenOptions.SectionName}:{nameof(AuthTokenOptions.SigningCertificateThumbprint)} and " +
                $"{nameof(AuthTokenOptions.EncryptionCertificateThumbprint)} are required outside Development. " +
                "Install the certificates in the CurrentUser/My store and configure their thumbprints.");
        }

        // Asked for explicitly by any host that must not touch the OS keystore. Checked before the
        // probe because the probe cannot tell "the store opens" from "the store is usable without
        // blocking", and on macOS those are different answers.
        if (tokenOptions.UseEphemeralKeys)
        {
            options.AddEphemeralSigningKey();
            options.AddEphemeralEncryptionKey();
            return;
        }

        if (CanPersistCertificates())
        {
            options.AddDevelopmentSigningCertificate();
            options.AddDevelopmentEncryptionCertificate();
            return;
        }

        options.AddEphemeralSigningKey();
        options.AddEphemeralEncryptionKey();
    }

    private static bool CanPersistCertificates()
    {
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Creates or refreshes the single first-party client on startup.
    /// <para>
    /// It resolves the application manager from a scope of its own: OpenIddict registers the managers
    /// <b>scoped</b>, and a hosted service that injects one directly fails at startup under scope
    /// validation. Failing to seed throws rather than logs — a missing client turns every token
    /// request into <c>invalid_client</c>, which is a far more confusing outage than not booting.
    /// </para>
    /// </summary>
    private sealed class FirstPartyClientSeeder(
        IServiceScopeFactory scopeFactory,
        IOptions<AuthTokenOptions> options) : IHostedService
    {
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            var settings = options.Value;

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = settings.ClientId,
                DisplayName = settings.ClientDisplayName,

                // A mobile app cannot keep a secret, so pretending it can buys nothing. The device
                // grant's own parameters, not a shared client secret, are what authenticate a login.
                ClientType = ClientTypes.Public,
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.Prefixes.GrantType + settings.DeviceGrantType,

                    // Without the offline_access scope permission the client may ask for it and be
                    // refused, and the refresh design quietly reduces to access tokens only.
                    Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                },
            };

            await using var scope = scopeFactory.CreateAsyncScope();
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var existing = await applications.FindByClientIdAsync(settings.ClientId, cancellationToken);
            if (existing is null)
            {
                await applications.CreateAsync(descriptor, cancellationToken);
                return;
            }

            // Re-applied on every boot so a permission added in code lands without a manual step.
            await applications.UpdateAsync(existing, descriptor, cancellationToken);
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
