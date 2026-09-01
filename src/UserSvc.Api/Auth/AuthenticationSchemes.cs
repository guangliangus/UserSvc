using OpenIddict.Validation.AspNetCore;

namespace UserSvc.Api.Auth;

/// <summary>
/// The authentication scheme names and the one claim type this service treats as load bearing.
/// <para>
/// <c>sid</c> is not in <c>OpenIddictConstants.Claims</c> at 7.6.1, so it has to be our own
/// constant. It was previously a bare string literal in two separate files, which is exactly how a
/// typo turns "the session was revoked" into "the token has no session and is therefore fine"
/// (decision 11) — one const, referenced everywhere.
/// </para>
/// </summary>
public static class AuthenticationSchemes
{
    /// <summary>The session id carried by every access token. See the type remarks for why this is
    /// hand-rolled rather than an OpenIddict constant.</summary>
    public const string SessionIdClaimType = "sid";

    /// <summary>Validates access tokens issued by the in-process OpenIddict server.</summary>
    public const string Bearer = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;

    /// <summary>Header-fabricated identities. Development only.</summary>
    public const string DevHeader = "DevHeader";

    /// <summary>
    /// Development-only policy scheme: a request carrying <c>Authorization: Bearer</c> is validated
    /// for real, anything else falls through to <see cref="DevHeader"/>. This is what lets the
    /// existing curl and integration-test workflow keep working while real tokens are also
    /// accepted on the same host.
    /// </summary>
    public const string DevelopmentPolicy = "DevelopmentPolicy";
}
