using System.Security.Cryptography;
using UserSvc.Application.Features.Registration;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Users;

namespace UserSvc.Application.Features.BackOffice.Accounts;

/// <summary>
/// Turns a back-office login identifier into the three forms a
/// <see cref="Domain.BackOffice.BackendIdentity"/> row stores, and supplies the handle a
/// freshly provisioned account starts with.
/// <para>
/// <b>Normalization is the highest-consequence function here.</b> The blind index is a plain hash
/// of whatever string it is handed, so two spellings of one mailbox produce two hashes - which is
/// to say two accounts for one person, and a partial unique index that no longer means what its
/// name says. Every flow that creates, looks up or rebinds a back-office identity must normalize
/// through this one function.
/// </para>
/// <para>
/// It is deliberately <i>not</i> the consumer plane's <see cref="IdentifierNormalizer"/> called
/// directly, for one reason: that one refuses an identity type it does not recognize, and the
/// back office has a third type - the employee number the corporate one-time-password service
/// authenticates. Refusing it there is right, because a typo must never become an unreachable
/// login identity; handling it here is right, because it is a real type on this plane. The phone
/// and email rules are delegated so the two planes cannot drift apart on the types they share.
/// </para>
/// <para>
/// Pure computation, so it is not a port and tests use the real thing.
/// </para>
/// </summary>
public static class BackOfficeIdentifiers
{
    /// <summary>The prefix of a generated handle, so an operator can tell at a glance that nobody
    /// chose this name.</summary>
    private const string GeneratedHandlePrefix = "User_";

    /// <summary>
    /// Brings an identifier to the one spelling that gets hashed.
    /// <para>
    /// Addresses are trimmed and lowercased; phone numbers keep their digits and nothing else; an
    /// employee number is trimmed and otherwise left exactly as the corporate directory spells it,
    /// because it is that system's key and not ours to reformat.
    /// </para>
    /// </summary>
    public static string Normalize(string identityType, string identifier)
    {
        var value = identifier ?? string.Empty;

        return identityType switch
        {
            BackendIdentityTypes.Email => IdentifierNormalizer.Normalize(IdentityTypes.Email, value),
            BackendIdentityTypes.Phone => IdentifierNormalizer.Normalize(IdentityTypes.Phone, value),
            _ => value.Trim(),
        };
    }

    /// <summary>
    /// The display fallback: enough of the identifier to recognize your own, not enough to deliver
    /// to or to enumerate with.
    /// <para>
    /// It exists because the ciphertext can stop being readable - a rotated or unavailable data key
    /// - and a directory that degraded to a blank column would look like a data-loss incident to
    /// every operator reading it. It is never a lookup key and never compared: only the blind index
    /// is.
    /// </para>
    /// </summary>
    public static string Mask(string identityType, string normalizedIdentifier)
    {
        var value = normalizedIdentifier ?? string.Empty;
        if (value.Length == 0)
        {
            return string.Empty;
        }

        switch (identityType)
        {
            case BackendIdentityTypes.Email:
                var separator = value.LastIndexOf('@');

                // Not an address after all - mask it like an opaque value rather than exposing it
                // whole because one character was missing.
                if (separator <= 0)
                {
                    return MaskTail(value, 2);
                }

                // The domain stays readable: it is not a secret, and it is what tells someone
                // whether the account they are looking at is the corporate one or the personal one.
                return string.Concat(value.AsSpan(0, 1), "***", value.AsSpan(separator));

            case BackendIdentityTypes.Phone:
                return MaskTail(value, 4);

            default:
                return MaskTail(value, 2);
        }
    }

    /// <summary>
    /// A handle for an account nobody named: the prefix plus eight hex characters from four random
    /// bytes.
    /// <para>
    /// No collision check, deliberately. Nothing keys on a handle - it is a display string, and the
    /// unique index lives on the identity's blind index - so a collision costs two accounts the
    /// same placeholder name until someone renames one, whereas a uniqueness loop would put a
    /// retry on the account-creation path for no benefit.
    /// </para>
    /// </summary>
    public static string GenerateHandle() =>
        GeneratedHandlePrefix + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4));

    /// <summary>Keeps the last <paramref name="visible"/> characters and stars out the rest, never
    /// revealing more than half of a short value.</summary>
    private static string MaskTail(string value, int visible)
    {
        var keep = Math.Min(visible, value.Length / 2);

        return keep <= 0
            ? new string('*', value.Length)
            : new string('*', value.Length - keep) + value[^keep..];
    }
}
