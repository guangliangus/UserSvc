using System.ComponentModel.DataAnnotations;

namespace UserSvc.Application.Features.BackOffice.SignIn;

/// <summary>
/// What a deployment has to supply for back-office sign-in, and the few knobs worth turning per
/// environment.
/// <para>
/// <b>Nothing here is <see cref="RequiredAttribute"/> and this section is deliberately not
/// validated at startup.</b> The one value that has no working default -
/// <see cref="SignInTicketKey"/> - is checked at the point of use instead, and a deployment that
/// has not supplied it gets a 500 <c>NOT_CONFIGURED</c> naming the key on the two sign-in
/// endpoints and nowhere else. Chaining <c>ValidateOnStart</c> onto it would stop the host booting
/// over a secret that consumer sign-in, registration, sessions and every integration test manage
/// perfectly well without - the failure mode docs/architecture.md records having been paid for
/// three times.
/// </para>
/// </summary>
public sealed class BackOfficeSignInOptions
{
    public const string SectionName = "BackOfficeSignIn";

    /// <summary>
    /// HMAC key for the sign-in ticket, as hex. At least 32 bytes (64 hex characters).
    /// <para>
    /// <b>Every replica must hold the same value.</b> The ticket is minted by whichever pod served
    /// the sign-in and redeemed by whichever pod serves the token request a moment later; a
    /// per-process key would fail that second request roughly (n-1)/n of the time behind a load
    /// balancer, which presents as "sign-in works sometimes".
    /// </para>
    /// <para>
    /// Empty by default rather than a fixed development value on purpose. A shipped default is a
    /// key an attacker also has, and a ticket forged under it names any account id it likes -
    /// which is the whole of back-office authentication. Missing configuration that refuses is
    /// recoverable; a known key that works is not.
    /// </para>
    /// </summary>
    public string SignInTicketKey { get; init; } = string.Empty;

    /// <summary>
    /// How long a sign-in ticket may be redeemed for. Short on purpose: its only legitimate use is
    /// the token request the client makes immediately after signing in, and it is a bearer
    /// credential for the account it names until it expires.
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:15", "00:10:00")]
    public TimeSpan SignInTicketLifetime { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Lifetime of a pre-tenant access token - the credential an operator holds while the context
    /// chooser is on screen. It reaches two endpoints, carries no refresh token and has to outlive
    /// nothing but one human decision.
    /// </summary>
    [Range(typeof(TimeSpan), "00:01:00", "00:30:00")]
    public TimeSpan PreTenantTokenLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Password sign-in attempts allowed per minute for one mailbox. See
    /// <see cref="BackOfficeSignInAppService"/> for why this counts attempts rather than
    /// failures.</summary>
    [Range(1, 1_000)]
    public int PasswordAttemptsPerMinute { get; init; } = 10;

    /// <summary>Password sign-in attempts allowed per hour for one mailbox.</summary>
    [Range(1, 10_000)]
    public int PasswordAttemptsPerHour { get; init; } = 60;

    /// <summary>One-time-password sign-in attempts allowed per minute for one employee number.
    /// Tighter than the password budget because each attempt spends a code somebody was sent.</summary>
    [Range(1, 1_000)]
    public int OtpAttemptsPerMinute { get; init; } = 5;

    /// <summary>One-time-password sign-in attempts allowed per hour for one employee number.</summary>
    [Range(1, 10_000)]
    public int OtpAttemptsPerHour { get; init; } = 20;
}
