using System.Security.Cryptography;

namespace UserSvc.Application.Features.BackOffice.Tenants;

/// <summary>
/// The one-time password minted when an administrator opens an account for somebody, or resets
/// one. Pure computation over a system RNG, so it is not a port - unit tests use the real thing.
/// </summary>
public static class InitialPasswordGenerator
{
    /// <summary>Look-alike glyphs are left out on purpose: this password is read off a screen or
    /// out of an e-mail and typed by hand, and a zero that turns out to be an O costs a support
    /// ticket.</summary>
    private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";

    private const string Lower = "abcdefghijkmnopqrstuvwxyz";

    private const string Digits = "23456789";

    private const int Length = 10;

    /// <summary>
    /// Ten characters with at least one of each class, so the result always satisfies the same
    /// password policy a person's own choice has to meet.
    /// <para>
    /// Every draw goes through <see cref="RandomNumberGenerator.GetInt32(int)"/> rather than
    /// <c>byte % alphabet.Length</c>: the naive form is biased towards the front of the alphabet
    /// whenever 256 is not a multiple of its length, which is most of the time. The final shuffle
    /// is what keeps the guaranteed characters from always landing in the first three positions.
    /// </para>
    /// </summary>
    public static string Generate()
    {
        const string all = Upper + Lower + Digits;

        var characters = new char[Length];
        characters[0] = Pick(Upper);
        characters[1] = Pick(Lower);
        characters[2] = Pick(Digits);

        for (var i = 3; i < Length; i++)
        {
            characters[i] = Pick(all);
        }

        RandomNumberGenerator.Shuffle<char>(characters);
        return new string(characters);
    }

    private static char Pick(string alphabet) => alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
}
