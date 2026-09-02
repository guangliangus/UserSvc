namespace UserSvc.Application.Features.BackOffice.Tenants;

/// <summary>
/// Audit actions this slice writes. They are read by the back office and by anyone answering
/// "who took this access away", so they are a contract: add, never rename.
/// </summary>
public static class IamAuditActions
{
    public const string MemberAdd = "MEMBER_ADD";

    public const string MemberRemove = "MEMBER_REMOVE";

    public const string MemberStatusUpdate = "MEMBER_STATUS_UPDATE";

    public const string MemberRolesUpdate = "MEMBER_ROLES_UPDATE";

    public const string MemberPasswordReset = "MEMBER_PASSWORD_RESET";

    public const string TenantSwitch = "TENANT_SWITCH";

    /// <summary>Audit target kinds.</summary>
    public const string MemberTarget = "member";

    /// <summary>The tenant type recorded for platform-side actions, which belong to no tenant.</summary>
    public const string PlatformTenantType = "platform";
}

/// <summary>Back-office account states, as this slice reads them.</summary>
public static class BackOfficeAccountStates
{
    /// <summary>Provisioned by HR. There is no locally minted password to reset - those accounts
    /// authenticate through the staff directory.</summary>
    public const string InternalOrigin = "INTERNAL";

    /// <summary>Opened by a back-office administrator, with a generated password.</summary>
    public const string ExternalOrigin = "EXTERNAL";

    /// <summary>The only status that carries authority.</summary>
    public const string Active = "ACTIVE";

    public const string Disabled = "DISABLED";
}

/// <summary>
/// The one display-name rule for back-office accounts. Pure string work, so not a port.
/// <para>
/// It exists because the roster, the audit trail, the shell header and the token all render a
/// person's name, and three different rules would have one person appear under three different
/// names in the same product.
/// </para>
/// </summary>
public static class BackOfficeNames
{
    /// <summary>Both name parts when both are there, the nickname otherwise.</summary>
    public static string Display(string? firstName, string? lastName, string? nickname)
    {
        var first = (firstName ?? string.Empty).Trim();
        var last = (lastName ?? string.Empty).Trim();

        return first.Length > 0 && last.Length > 0
            ? JoinFullName(first, last)
            : (nickname ?? string.Empty).Trim();
    }

    /// <summary>Family name first and unseparated for CJK names, given name first with a space
    /// otherwise. Getting this backwards is not a formatting nit - it renders the name wrong.</summary>
    public static string JoinFullName(string firstName, string lastName)
    {
        var first = firstName.Trim();
        var last = lastName.Trim();

        if (first.Length == 0 || last.Length == 0)
        {
            return (last + first).Trim();
        }

        return IsIdeographic(first) || IsIdeographic(last) ? last + first : first + " " + last;
    }

    /// <summary>Written as code points rather than as sample characters so this file stays inside
    /// the English-source rule the architecture tests enforce.</summary>
    private static bool IsIdeographic(string value) =>
        value.Any(c => c is >= (char)0x3040 and <= (char)0x30FF     // kana
            or >= (char)0x4E00 and <= (char)0x9FFF                  // CJK unified ideographs
            or >= (char)0xAC00 and <= (char)0xD7AF);                // hangul syllables
}
