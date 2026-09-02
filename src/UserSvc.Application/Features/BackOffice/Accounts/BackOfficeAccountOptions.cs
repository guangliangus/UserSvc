using System.ComponentModel.DataAnnotations;

namespace UserSvc.Application.Features.BackOffice.Accounts;

/// <summary>Settings for the back-office account flows.</summary>
public sealed class BackOfficeAccountOptions
{
    public const string SectionName = "BackOffice";

    /// <summary>
    /// The corporate mail domains an internal back-office account may use, comma separated. A
    /// leading <c>@</c> is optional per entry.
    /// <para>
    /// It gates <b>registration for everyone</b>, and sign-in only for accounts whose origin is
    /// INTERNAL - an external B2B partner authenticates with whatever mailbox they have. Shipping
    /// the group's real domains as the default is deliberate: an empty allow-list refuses every
    /// internal registration, which is safe but presents as a total outage with no obvious cause,
    /// and the value is not a secret.
    /// </para>
    /// </summary>
    [Required]
    public string InternalDomains { get; set; } = "@liontravel.com,@xinflight.com";

    /// <summary>Default page size for the back-office directory when the client states none.</summary>
    [Range(1, 100)]
    public int DefaultPageSize { get; set; } = 20;

    /// <summary>
    /// Self-service password resets one source address may submit per minute.
    /// <para>
    /// Sized for a shared egress address rather than for one person, exactly like the send-code
    /// budget in front of this flow: nothing in this host trusts a forwarded-headers hop, so behind
    /// a gateway this counter counts the gateway. A tight number here would not throttle an
    /// attacker, it would cap how many operators can reset a password at all.
    /// </para>
    /// </summary>
    [Range(1, 100_000)]
    public int PasswordResetPerSourcePerMinute { get; set; } = 100;

    /// <summary>Self-service password resets one source address may submit per hour, for the slow
    /// flood the per-minute budget never notices.</summary>
    [Range(1, 1_000_000)]
    public int PasswordResetPerSourcePerHour { get; set; } = 500;

    /// <summary>
    /// Where the back office signs in, sent as the <c>login_path</c> variable of every credential
    /// e-mail.
    /// <para>
    /// Blank by default and deliberately not <c>[Required]</c>: a deployment with no back office in
    /// front of it still boots, and the only thing that stops working is the credential mail, which
    /// reports itself as not sent. The template treats the variable as mandatory, so sending
    /// without it would be rejected by the notification service - the sender checks it first and
    /// refuses locally instead, where the log line can say why.
    /// </para>
    /// </summary>
    public string LoginUrl { get; set; } = string.Empty;
}
