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
}
