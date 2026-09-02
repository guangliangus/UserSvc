using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace UserSvc.Application.Features.Registration;

/// <summary>
/// Argon2id password hashing, in the PHC string format.
/// <para>
/// <b>Only Argon2id, with no legacy branch.</b> The Go service this replaces hashed with bcrypt,
/// but it carries zero consumer accounts - verified against the live database - so there is no
/// stored bcrypt hash to verify and no dual-algorithm dispatch to write. Writing one anyway would
/// have meant shipping a bcrypt dependency and an upgrade-on-login path for a set that is provably
/// empty.
/// </para>
/// <para>
/// The algorithm is still recorded in <c>users.password_algo</c> and repeated inside the encoded
/// hash. That is not redundancy for its own sake: a hash column with no algorithm column is how a
/// future migration becomes impossible, because nothing can tell which rows still need rehashing
/// without trying to verify them. The column answers "which rows", the PHC string answers "with
/// which parameters".
/// </para>
/// <para>
/// It is not a port - given a password it is pure computation, so unit tests use the real thing
/// (see the Ports rule in docs/architecture.md, and <c>IdentifierProtector</c> as the precedent).
/// </para>
/// </summary>
public sealed class PasswordHasher
{
    /// <summary>Written to <c>users.password_algo</c>. The column comment lists the allowed values.</summary>
    public const string AlgorithmName = "ARGON2ID";

    /// <summary>
    /// 19 MiB of memory, two passes, one lane - OWASP's baseline Argon2id configuration and the
    /// low-memory end of RFC 9106's second recommended option.
    /// <para>
    /// The parameters were picked around one number: <b>memory times concurrency</b>. Memory is
    /// what actually costs an attacker, because a GPU or ASIC can multiply cores far more cheaply
    /// than it can multiply memory bandwidth - but every concurrent hash on our side holds its
    /// full working set at once, so 19 MiB x 64 simultaneous registrations is 1.2 GiB of
    /// resident memory that the container limit has to cover. Registration is a rare, rate-limited
    /// operation, which is what makes this affordable; raising the memory further would trade a
    /// bounded attacker gain for an unbounded self-inflicted one.
    /// </para>
    /// <para>
    /// <see cref="Lanes"/> is 1 for the same reason: extra lanes only pay off when the caller can
    /// give them extra cores, and this process would rather spend its cores on other requests.
    /// Iterations stay at the minimum the memory size justifies - they cost us linearly and cost
    /// the attacker linearly, so they are the weakest of the three knobs.
    /// </para>
    /// <para>
    /// These constants are safe to raise later precisely because every hash carries the parameters
    /// it was made with; old rows keep verifying and can be rehashed on the next sign-in.
    /// </para>
    /// </summary>
    private const int MemoryKibibytes = 19 * 1024;

    private const int Iterations = 2;
    private const int Lanes = 1;

    /// <summary>RFC 9106 defaults: 128-bit salt, 256-bit tag.</summary>
    private const int SaltLength = 16;

    private const int HashLength = 32;

    /// <summary>The Argon2 version PHC encodes as <c>v=19</c> (0x13), which is Argon2 1.3.</summary>
    private const int Version = 19;

    /// <summary>
    /// The largest stored parameters <see cref="Verify"/> will honour, an order of magnitude above
    /// anything this service writes.
    /// <para>
    /// Verification derives with the parameters found <b>in the row</b>, which is what keeps old
    /// hashes verifiable after the constants are raised - and which also means a row is an
    /// instruction to allocate memory. Anyone who can write to <c>password_hash</c> could otherwise
    /// store <c>m=1073741824</c> and turn one sign-in attempt into a terabyte allocation. A row
    /// outside these bounds is treated as unreadable and fails verification, so the blast radius of
    /// a tampered row is that nobody can sign into it.
    /// </para>
    /// </summary>
    private const int MaxMemoryKibibytes = 256 * 1024;

    private const int MaxIterations = 16;
    private const int MaxLanes = 16;

    /// <summary>
    /// Hashes a password into <c>$argon2id$v=19$m=...,t=...,p=...$salt$hash</c>, the format the
    /// reference implementation and every other Argon2 library reads. Storing the parameters
    /// beside the digest is what makes them changeable.
    /// </summary>
    /// <exception cref="ArgumentException">The password is empty. The validator refuses one long
    /// before this point; the underlying Argon2 implementation also refuses to derive from one, so
    /// failing here says why rather than surfacing its message from three frames down.</exception>
    public string Hash(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = Derive(password, salt, MemoryKibibytes, Iterations, Lanes, HashLength);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"$argon2id$v={Version}$m={MemoryKibibytes},t={Iterations},p={Lanes}${Encode(salt)}${Encode(hash)}");
    }

    /// <summary>
    /// Verifies a candidate against a stored PHC string, using the parameters recorded in that
    /// string rather than the current constants - which is the whole point of storing them.
    /// <para>
    /// A malformed or unreadable stored value returns <c>false</c> instead of throwing. A row
    /// whose hash cannot be parsed is a row nobody can sign in to, and that is exactly the answer;
    /// turning it into a 500 would tell an attacker which accounts have damaged hashes.
    /// </para>
    /// <para>
    /// That silence has a cost, and it belongs to the caller: a damaged row is indistinguishable
    /// here from a wrong password, so the sign-in flow - not this class, which holds no logger
    /// precisely because it is pure computation - is where a stored value that does not begin with
    /// <c>$argon2id$</c> must be logged. Without that, "nobody can sign in to this account" is a
    /// fact only the user ever learns.
    /// </para>
    /// </summary>
    public bool Verify(string password, string encoded)
    {
        // No stored hash can have come from an empty password, because Hash refuses to make one -
        // so there is nothing for it to match, and the derivation below would throw rather than
        // return false.
        if (string.IsNullOrEmpty(password))
        {
            return false;
        }

        var fields = encoded.Split('$');

        // ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash] - the leading empty field is
        // the string's own leading '$'.
        if (fields.Length != 6 || !string.Equals(fields[1], "argon2id", StringComparison.Ordinal))
        {
            return false;
        }

        var parameters = fields[3].Split(',');
        if (parameters.Length != 3
            || !TryReadParameter(parameters[0], "m=", MaxMemoryKibibytes, out var memory)
            || !TryReadParameter(parameters[1], "t=", MaxIterations, out var iterations)
            || !TryReadParameter(parameters[2], "p=", MaxLanes, out var lanes))
        {
            return false;
        }

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Decode(fields[4]);
            expected = Decode(fields[5]);
        }
        catch (FormatException)
        {
            return false;
        }

        if (salt.Length == 0 || expected.Length == 0)
        {
            return false;
        }

        var actual = Derive(password, salt, memory, iterations, lanes, expected.Length);

        // Constant time: a byte-by-byte comparison leaks how much of a guessed digest was right,
        // which over enough attempts is a digest oracle.
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static byte[] Derive(
        string password,
        byte[] salt,
        int memoryKibibytes,
        int iterations,
        int lanes,
        int length)
    {
        // Synchronous on purpose. This burns roughly 20-40 ms of CPU on one thread; handing it to
        // another thread would not make it cheaper, and registration is not a hot path.
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memoryKibibytes,
            Iterations = iterations,
            DegreeOfParallelism = lanes,
        };

        return argon2.GetBytes(length);
    }

    private static bool TryReadParameter(string field, string prefix, int maximum, out int value)
    {
        value = 0;

        return field.StartsWith(prefix, StringComparison.Ordinal)
               && int.TryParse(field[prefix.Length..], CultureInfo.InvariantCulture, out value)
               && value > 0
               && value <= maximum;
    }

    /// <summary>PHC uses unpadded standard base64, not base64url.</summary>
    private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=');

    private static byte[] Decode(string value) =>
        Convert.FromBase64String(value.PadRight(value.Length + ((4 - (value.Length % 4)) % 4), '='));
}
