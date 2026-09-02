using UserSvc.Application.Security;

namespace UserSvc.Application.Features.Verification;

/// <summary>
/// How the three secrets in <c>verification_codes</c> become columns. Shared by the repository
/// adapter, which writes and matches them, and by risk control, which counts rows by the same
/// hashes - a second implementation anywhere would produce hashes that silently never match.
/// <para>
/// Everything here goes through <see cref="IdentifierProtector"/>, so every column is peppered with
/// a key held outside the database (decision 13). That matters most for the code itself: a
/// verification code is six digits, so an un-peppered digest of it is reversible by anyone holding
/// a database dump in the time it takes to enumerate a million values. With the pepper, reading the
/// table is not enough - an attacker needs the key store too.
/// </para>
/// </summary>
public static class VerificationHashing
{
    /// <summary>
    /// Blind index over the target as the caller typed it, trimmed and lowercased and nothing else.
    /// <para>
    /// <b>This is deliberately not the identity-type-aware normalization</b> that
    /// <c>user_identities</c> uses: a phone reaching this table hashes over its literal form, so
    /// <c>13812345678</c> and <c>+8613812345678</c> are two different targets here even when they
    /// name the same account. That is safe because send, verify and consume all use this same
    /// function, so a flow is self-consistent end to end; it is only the cross-table comparison
    /// with a login identity that would be wrong, and no code path makes one.
    /// </para>
    /// </summary>
    public static string HashTarget(IdentifierProtector protector, string target)
    {
        ArgumentNullException.ThrowIfNull(protector);
        return protector.Hash(Normalize(target));
    }

    /// <summary>
    /// Blind index over the <c>X-Device-ID</c> header, hashed exactly like a target so the
    /// device-dimension row count matches what was written.
    /// <para>
    /// A caller that sent no device id stores the empty string, not the hash of one, and the
    /// difference is what keeps the device count honest. Every anonymous send shares that empty
    /// value, so if a blank device id also <i>hashed</i> to something the column holds, counting it
    /// would aggregate every anonymous caller in the deployment as though they were one busy
    /// device. Because the hash of a blank value is a digest no row carries, the count answers zero
    /// instead - those rows are never attributed to anyone.
    /// </para>
    /// </summary>
    public static string HashDeviceId(IdentifierProtector protector, string? deviceId)
    {
        ArgumentNullException.ThrowIfNull(protector);
        return string.IsNullOrWhiteSpace(deviceId) ? string.Empty : protector.Hash(Normalize(deviceId));
    }

    /// <summary>
    /// Blind index over a code or a ticket. <b>No trimming and no case folding</b>: both are
    /// machine-generated secrets compared for exact equality, and normalizing them would widen the
    /// set of strings that unlock an account for no benefit to anyone typing correctly.
    /// </summary>
    public static string HashSecret(IdentifierProtector protector, string secret)
    {
        ArgumentNullException.ThrowIfNull(protector);
        return protector.Hash(secret);
    }

    private static string Normalize(string value) => value.Trim().ToLowerInvariant();
}
