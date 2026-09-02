using System.ComponentModel.DataAnnotations;

namespace UserSvc.Application.Features.Verification;

/// <summary>
/// Verification-code lifetimes and the per-IP send budget. Validated at startup: a bad value
/// refuses to boot rather than being discovered when someone cannot sign in.
/// </summary>
public sealed class VerificationOptions
{
    public const string SectionName = "Verification";

    /// <summary>
    /// How long a code stays verifiable. The lower bound is 30 seconds rather than something
    /// friendlier because the notification template renders this as a whole number of minutes and
    /// floors at 1 - below a minute the message and the truth start to disagree, and under 30
    /// seconds nobody can read an SMS and type it in time.
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:30", "01:00:00")]
    public TimeSpan CodeExpires { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How long the ticket minted by a successful verify stays usable. It bounds the flow that
    /// follows - registration, password reset, binding - not the typing of the code, which is why
    /// it is a separate budget and not derived from <see cref="CodeExpires"/>.
    /// <para>
    /// The Go original clamped a non-positive value to ten minutes at runtime. Here the range does
    /// that job at startup instead: a zero would have meant every ticket expiring the instant it
    /// was issued, and a boot failure names the misconfiguration while a silent clamp hides it.
    /// </para>
    /// </summary>
    [Range(typeof(TimeSpan), "00:01:00", "01:00:00")]
    public TimeSpan TicketTtl { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Issue the fixed code <c>123456</c> instead of a random one, so local and test flows can sign
    /// in without a mailbox. <b>Turning this on in an environment reachable from the internet hands
    /// every account to anyone who knows the address on it</b> - it belongs in Development
    /// configuration only, and never in the base appsettings file.
    /// </summary>
    public bool UseMockCode { get; init; }

    /// <summary>
    /// Codes one client IP may request per minute. Sized for shared egress (office NAT, carrier
    /// CGNAT) rather than for one person: per-account and per-device throttling is risk control's
    /// job, and this budget only exists to stop a single host flooding the endpoint.
    /// </summary>
    [Range(1, 100_000)]
    public int SendPerIpPerMinute { get; init; } = 100;

    /// <summary>Codes one client IP may request per hour, for the slow flood the per-minute
    /// budget never notices.</summary>
    [Range(1, 1_000_000)]
    public int SendPerIpPerHour { get; init; } = 500;
}
