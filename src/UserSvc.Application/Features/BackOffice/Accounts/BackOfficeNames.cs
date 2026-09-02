using System.Text.RegularExpressions;

namespace UserSvc.Application.Features.BackOffice.Accounts;

/// <summary>
/// How a back-office person's name is split, composed and displayed, and how a corporate mailbox is
/// recognized.
/// <para>
/// <b>Every surface must compose a display name the same way</b>, which is the reason these live in
/// one place. The account row keeps a given name, a family name and a handle; what a screen shows is
/// <see cref="DisplayName"/> of the three. When the member list composed them and the header did
/// not, the same person appeared as two people - and the search box could not find either, because
/// an operator types what they see.
/// </para>
/// <para>
/// Not a port: given a string these are pure functions, so tests use the real thing.
/// </para>
/// </summary>
public static partial class BackOfficeNames
{
    /// <summary>
    /// Splits one HR-supplied name into a given name and a family name.
    /// <para>
    /// Two rules, because two naming systems arrive through the same field. A name containing
    /// whitespace is read the Western way - the first token is the given name and everything after
    /// it is the family name, so a compound surname survives. A name without whitespace that
    /// contains non-ASCII characters is read the CJK way: the first character is the family name and
    /// the rest is the given name.
    /// </para>
    /// <para>
    /// <b>Known limitation, deliberately kept:</b> the two-character Chinese compound surnames
    /// (such as the ones beginning European-style with two ideographs) are mis-split, because
    /// nothing in the input distinguishes them from a single-character surname with a
    /// two-character given name. The alternative is a surname dictionary that has to be maintained
    /// forever and is wrong for anyone not in it. The split only ever affects display, never
    /// identity or matching, and an operator can correct the two fields by hand.
    /// </para>
    /// </summary>
    public static (string First, string Last) SplitFullName(string? fullName)
    {
        var trimmed = (fullName ?? string.Empty).Trim();
        if (trimmed.Length == 0)
        {
            return (string.Empty, string.Empty);
        }

        var parts = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 1)
        {
            return (parts[0], string.Join(' ', parts.Skip(1)));
        }

        // No whitespace. Non-ASCII means a CJK name, where the family name comes first and is
        // normally one character. Enumerated by text element rather than by char so a surrogate
        // pair - a rare ideograph outside the basic plane - is not cut in half.
        if (!IsAscii(trimmed))
        {
            var enumerator = System.Globalization.StringInfo.GetTextElementEnumerator(trimmed);
            if (enumerator.MoveNext())
            {
                var family = (string)enumerator.Current;
                return (trimmed[family.Length..], family);
            }
        }

        return (trimmed, string.Empty);
    }

    /// <summary>
    /// Composes a given name and a family name back into one string, in the order the name's own
    /// script uses: family name first and unseparated when either part is non-ASCII, given name
    /// first with a space when both are ASCII. Either part empty yields the other unchanged.
    /// <para>
    /// The space is not cosmetic. Inserting one into a CJK name makes it read as two names, and
    /// omitting it from a Latin one runs the two together - both are wrong in a way the person
    /// whose name it is notices immediately.
    /// </para>
    /// </summary>
    public static string JoinFullName(string? first, string? last)
    {
        var firstPart = (first ?? string.Empty).Trim();
        var lastPart = (last ?? string.Empty).Trim();

        if (firstPart.Length == 0)
        {
            return lastPart;
        }

        if (lastPart.Length == 0)
        {
            return firstPart;
        }

        return IsAscii(firstPart) && IsAscii(lastPart)
            ? $"{firstPart} {lastPart}"
            : lastPart + firstPart;
    }

    /// <summary>
    /// What every screen shows for a back-office account: the composed full name when both halves
    /// are present, and otherwise the stored handle, unchanged.
    /// <para>
    /// The fallback matters as much as the composition. An account seeded from a mailbox has a
    /// handle and no name, and composing from one half would display a surname on its own.
    /// </para>
    /// </summary>
    public static string DisplayName(string? first, string? last, string? nickname)
    {
        var firstPart = (first ?? string.Empty).Trim();
        var lastPart = (last ?? string.Empty).Trim();

        return firstPart.Length == 0 || lastPart.Length == 0
            ? nickname ?? string.Empty
            : JoinFullName(firstPart, lastPart);
    }

    /// <summary>Trim and lowercase - the spelling a handle is compared in, never the spelling it is
    /// displayed in. Display keeps whatever casing the person chose.</summary>
    public static string NormalizeNickname(string? nickname) =>
        (nickname ?? string.Empty).Trim().ToLowerInvariant();

    /// <summary>
    /// The part of an address before the <c>@</c>, lowercased - the handle a freshly provisioned
    /// account starts life with. A string with no local part at all is normalized whole rather than
    /// yielding an empty handle, because an account with no display name renders as a blank row.
    /// </summary>
    public static string EmailLocalPart(string? email)
    {
        var value = email ?? string.Empty;
        var separator = value.IndexOf('@', StringComparison.Ordinal);

        return separator > 0 ? NormalizeNickname(value[..separator]) : NormalizeNickname(value);
    }

    /// <summary>
    /// Whether the whole string is an email address. Anchored on purpose: a substring match would
    /// treat a name containing an address as an address, and the directory search branches on this
    /// to decide whether to look in the encrypted identity table or in the name columns.
    /// </summary>
    public static bool IsEmail(string? value) => EmailPattern().IsMatch((value ?? string.Empty).Trim());

    /// <summary>
    /// Parses the corporate domain allow-list - a comma-separated setting - into the domains an
    /// internal account may sign in from. Entries are lowercased and given a leading <c>@</c> if
    /// they lack one, so <c>example.com</c> and <c>@example.com</c> configure the same thing and a
    /// missing sign cannot silently widen the rule to every domain ending in those characters.
    /// </summary>
    public static IReadOnlyList<string> InternalDomains(string? configured) =>
    [
        .. (configured ?? string.Empty)
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(entry => entry.ToLowerInvariant())
            .Select(entry => entry.StartsWith('@') ? entry : "@" + entry)
            .Where(entry => entry.Length > 1)
    ];

    /// <summary>
    /// Whether an address belongs to one of the allowed domains.
    /// <para>
    /// The comparison starts at the <b>last</b> <c>@</c>, which is the only one that decides where
    /// mail goes. Taking the first would let <c>attacker@evil.example@corp.example</c> - or the
    /// quoted local parts RFC 5321 permits - present itself as a corporate address.
    /// </para>
    /// </summary>
    public static bool EmailInDomains(string? email, IReadOnlyList<string> domains)
    {
        ArgumentNullException.ThrowIfNull(domains);

        var value = (email ?? string.Empty).Trim().ToLowerInvariant();
        var separator = value.LastIndexOf('@');

        // No local part, no domain part, or nothing after the sign: not an address, so not one of
        // ours. An address ending in '@' would otherwise match a domain entry of "@".
        if (separator <= 0 || separator == value.Length - 1)
        {
            return false;
        }

        var domain = value[separator..];

        return domains.Any(allowed => string.Equals(domain, allowed, StringComparison.Ordinal));
    }

    private static bool IsAscii(string value) => value.All(char.IsAscii);

    /// <summary>
    /// Source-generated so the pattern is compiled once at build time rather than parsed on every
    /// call, and so the analyzer can prove it terminates.
    /// </summary>
    [GeneratedRegex(
        @"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex EmailPattern();
}
