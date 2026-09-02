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

    /// <summary>
    /// Failed password sign-ins allowed per minute for one mailbox, after which it is locked out
    /// for the rest of the window.
    /// <para>
    /// <b>Failures, not attempts</b> - the counter moves only when a credential is wrong, and a
    /// successful sign-in clears it. That is what the specification's steps describe and what these
    /// numbers were chosen for. The name changed with the behaviour: the old one said "attempts"
    /// and the code counted attempts, so a correct password spent budget and ten a minute described
    /// a human who mistypes rather than a lockout. A deployment that had overridden
    /// <c>BackOfficeSignIn__PasswordAttemptsPerMinute</c> has to be re-pointed at this name; the
    /// default is unchanged, so one that had not is unaffected.
    /// </para>
    /// </summary>
    [Range(1, 1_000)]
    public int PasswordFailuresPerMinute { get; init; } = 10;

    /// <summary>Failed password sign-ins allowed per hour for one mailbox. The slower budget, which
    /// is what catches an attacker pacing themselves just under the per-minute one.</summary>
    [Range(1, 10_000)]
    public int PasswordFailuresPerHour { get; init; } = 60;

    /// <summary>
    /// Failed password sign-ins allowed per minute from one client address, across every mailbox it
    /// tries.
    /// <para>
    /// <b>What it is for.</b> Ten failures a minute per mailbox does not bound one password tried
    /// against ten thousand mailboxes - every one of them is on its first failure, so the
    /// per-mailbox budget never fires at all. This is the dimension that notices.
    /// </para>
    /// <para>
    /// <b>Why 30 rather than something near the per-mailbox figure.</b> A corporate office reaches
    /// this service through one egress address, so the subject here is often a whole floor rather
    /// than a person. Three hundred staff signing in across a Monday morning, mistyping at the few
    /// per cent people do, produce single digits of failures in their busiest minute; 30 leaves
    /// about an order of magnitude of headroom, whereas a value near 10 would let one clumsy typist
    /// lock out everyone sharing their address. It still does its job: a spray from one address
    /// gets 30 guesses a minute instead of as many as it likes.
    /// </para>
    /// <para>
    /// Raise it for a deployment behind a single very large NAT. The signature of it being too
    /// small - as opposed to an actual attack - is 429s on this dimension arriving for many
    /// different mailboxes at once, all of which then succeed on a retry.
    /// </para>
    /// </summary>
    [Range(1, 100_000)]
    public int PasswordFailuresPerSourcePerMinute { get; init; } = 30;

    /// <summary>
    /// Failed password sign-ins allowed per hour from one client address.
    /// <para>
    /// 200 an hour is the figure that actually bounds a spray: one address gets under five thousand
    /// guesses a day, so trying a single password against ten thousand mailboxes takes days from
    /// one source and needs a botnet to be worth doing. It sits above what a NAT'd office produces
    /// - a thousand staff at a few per cent typo rate is on the order of a hundred failures an hour
    /// - and below what an attacker would need to pace themselves under the per-minute budget all
    /// day, which is the loophole a generous hourly figure would leave open.
    /// </para>
    /// </summary>
    [Range(1, 1_000_000)]
    public int PasswordFailuresPerSourcePerHour { get; init; } = 200;

    /// <summary>
    /// One-time-password sign-in <b>attempts</b> allowed per minute for one employee number.
    /// <para>
    /// Attempts rather than failures, unlike the password door, and tighter: every attempt here is
    /// an HTTP call to the corporate directory about a code somebody was sent, so arriving at all
    /// is the thing worth bounding. A successful sign-in still clears the budget, so only
    /// consecutive attempts accumulate.
    /// </para>
    /// </summary>
    [Range(1, 1_000)]
    public int OtpAttemptsPerMinute { get; init; } = 5;

    /// <summary>One-time-password sign-in attempts allowed per hour for one employee number.</summary>
    [Range(1, 10_000)]
    public int OtpAttemptsPerHour { get; init; } = 20;
}
