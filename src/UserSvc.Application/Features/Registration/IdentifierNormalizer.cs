using System.Text;
using UserSvc.Domain.Users;

namespace UserSvc.Application.Features.Registration;

/// <summary>
/// Brings an identifier to the one spelling that gets hashed into <c>identifier_hash</c>.
/// <para>
/// <b>This is the highest-consequence function in the slice</b> and it is worth saying why. The
/// blind index is a plain HMAC of whatever string is handed to it (decision 13), so two spellings
/// of the same address produce two different hashes: normalize inconsistently and the partial
/// unique index stops meaning "one account per identifier". Every module that binds or looks up a
/// login identity - registration, sign-in, binding - must run this exact function.
/// </para>
/// <para>
/// <b>It is not the function that hashes a verification target.</b> That is
/// <c>VerificationHashing.HashTarget</c>, which trims and lowercases and stops there, so a phone
/// number reaches <c>verification_codes</c> in its literal form. The two are deliberately
/// different because they answer different questions: that table asks "did this exact string get a
/// code", while this one asks "is this the same person's phone number, however they typed it".
/// Anything that spends a ticket must pass the raw target to the consumer and the normalized value
/// to this - <see cref="RegistrationAppService"/> is the worked example.
/// </para>
/// <para>
/// It is not a port: given a string it is pure computation, so tests use the real thing and there
/// is no boundary to invert (see the Ports rule in docs/architecture.md).
/// </para>
/// </summary>
public static class IdentifierNormalizer
{
    /// <summary>
    /// Maps the wire value onto <see cref="IdentityTypes"/>. Matching is case-insensitive because
    /// the Go service spelled these lowercase and the mobile clients still do.
    /// </summary>
    public static bool IsPhone(string identityType) =>
        string.Equals(identityType, IdentityTypes.Phone, StringComparison.OrdinalIgnoreCase);

    public static bool IsEmail(string identityType) =>
        string.Equals(identityType, IdentityTypes.Email, StringComparison.OrdinalIgnoreCase);

    public static bool IsSupportedIdentityType(string identityType) =>
        IsPhone(identityType) || IsEmail(identityType);

    /// <summary>
    /// Resolves the wire value to the stored constant. Unlike the Go original - which treated
    /// anything that was not <c>"phone"</c> as an email - an unrecognized value is rejected here.
    /// Silently filing a typo under EMAIL creates a login identity the caller can never reproduce.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The value is neither PHONE nor EMAIL. Callers reachable from HTTP check
    /// <see cref="IsSupportedIdentityType"/> first and answer 400; reaching this exception means a
    /// caller skipped that, which is a bug in the caller and not the client's fault.
    /// </exception>
    public static string ResolveIdentityType(string identityType)
    {
        if (IsPhone(identityType))
        {
            return IdentityTypes.Phone;
        }

        if (IsEmail(identityType))
        {
            return IdentityTypes.Email;
        }

        throw new ArgumentOutOfRangeException(
            nameof(identityType),
            identityType,
            $"Identity type must be {IdentityTypes.Phone} or {IdentityTypes.Email}.");
    }

    /// <summary>
    /// Email addresses are lowercased whole - the local part is technically case-sensitive per
    /// RFC 5321, but no mail provider anyone signs up with treats it that way, and honouring the
    /// RFC here would hand two accounts to one mailbox.
    /// <para>
    /// Phone numbers keep their digits and lose everything else, <b>the leading plus included</b>.
    /// The validator accepts a number with or without it - so do the verification endpoints - and
    /// keeping it would make <c>+886912345678</c> and <c>886912345678</c> two different blind
    /// indexes, which is to say two accounts for one telephone. The cost of collapsing them is a
    /// real one and worth naming: a national number that happens to read like another country's
    /// international form would collide. That needs a national number of 12 or more digits
    /// beginning with another country's calling code, whereas the duplicate-account failure needs
    /// only a user who typed the plus once and not the next time.
    /// </para>
    /// <para>
    /// The Go original additionally prefixed bare 11-digit mainland-China numbers with +86. That
    /// default is dropped: it silently binds a Taiwanese number to a mainland one for anyone who
    /// types 11 digits, and inventing a country code is a worse lie than storing the digits given.
    /// </para>
    /// </summary>
    public static string Normalize(string identityType, string identifier)
    {
        var trimmed = identifier.Trim();

        if (IsEmail(identityType))
        {
            return trimmed.ToLowerInvariant();
        }

        var digits = new StringBuilder(trimmed.Length);
        foreach (var character in trimmed)
        {
            // Kept as a positive test rather than a list of punctuation to drop: a list can only
            // ever be as complete as the formats someone thought of, and the fullwidth digits and
            // non-breaking spaces a mobile keyboard can produce are exactly what it would miss.
            if (char.IsAsciiDigit(character))
            {
                digits.Append(character);
            }
        }

        return digits.ToString();
    }
}
