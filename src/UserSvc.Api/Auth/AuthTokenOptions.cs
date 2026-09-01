using System.ComponentModel.DataAnnotations;

namespace UserSvc.Api.Auth;

/// <summary>
/// The OpenIddict server's deployment-specific knobs (decision 10). Token lifetimes deliberately
/// live in <c>AuthSessionOptions</c> instead: the access-token lifetime doubles as the TTL of the
/// Redis revocation entries, and two settings that must agree are one setting.
/// <para>
/// The token endpoint path is deliberately <b>not</b> here either. It has to equal the MVC route of
/// <c>TokenController</c>, and a route cannot be read from configuration, so a setting for it could
/// only ever disagree with the route - producing a 404 with no other symptom. It is the single
/// const <c>TokenController.TokenEndpointPath</c>.
/// </para>
/// <para>
/// Every string here ships with a working default, because <c>[Required]</c> rejects the empty
/// string — a blank placeholder in appsettings would refuse to boot rather than fall back.
/// </para>
/// </summary>
public sealed class AuthTokenOptions
{
    public const string SectionName = "AuthToken";

    /// <summary>
    /// The issuer written into tokens. Leave empty to let OpenIddict infer it from the request,
    /// which is wrong the moment a gateway terminates TLS on a different host name — set it
    /// explicitly in any deployment that has one.
    /// </summary>
    public string Issuer { get; init; } = string.Empty;

    /// <summary>The single first-party client. Public: a mobile app cannot keep a secret.</summary>
    [Required]
    public string ClientId { get; init; } = "usersvc-app";

    [Required]
    public string ClientDisplayName { get; init; } = "UserSvc first-party client";

    /// <summary>
    /// Thumbprint of the token-signing certificate in the CurrentUser/My store. Empty means
    /// "Development only": outside Development the host refuses to start rather than sign with an
    /// ephemeral key, which would invalidate every token on restart and make two replicas reject
    /// each other's tokens - an outage that looks like a random bug.
    /// </summary>
    public string SigningCertificateThumbprint { get; init; } = string.Empty;

    /// <summary>Thumbprint of the token-encryption certificate. Same rule as
    /// <see cref="SigningCertificateThumbprint"/>.</summary>
    public string EncryptionCertificateThumbprint { get; init; } = string.Empty;

    /// <summary>
    /// Sign and encrypt with in-memory keys that die with the process, instead of certificates in
    /// the OS keystore.
    /// <para>
    /// This exists because probing the keystore is not enough. On macOS the CurrentUser/My store
    /// opens successfully in a test host and then <b>blocks</b> when the private key is actually
    /// used, so token generation hangs with no error and no timeout - the failure looks like a
    /// deadlock in OpenIddict rather than a keychain prompt nobody can answer. Any non-interactive
    /// host - integration tests, CI, a container - should set this to true and stop asking the
    /// operating system for permission.
    /// </para>
    /// <para>Development only. Outside it, the certificate thumbprints are required.</para>
    /// </summary>
    public bool UseEphemeralKeys { get; init; }

    /// <summary>
    /// The password-less device-login grant. It is a private extension, so it carries our own URN:
    /// a bare name risks colliding with a grant type a future OAuth extension defines.
    /// </summary>
    [Required]
    public string DeviceGrantType { get; init; } = "urn:usersvc:params:oauth:grant-type:device";
}
