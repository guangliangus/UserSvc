using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using LegacyBcrypt = BCrypt.Net.BCrypt;
using LegacyBcryptSaltParseException = BCrypt.Net.SaltParseException;

namespace UserSvc.Application.Features.Registration;

/// <summary>
/// Which algorithm a stored password string says it was made with. Every format this service reads
/// carries its own algorithm name, which is what makes prefix dispatch sound rather than a guess.
/// </summary>
public enum StoredPasswordAlgorithms
{
    /// <summary>Nothing this service can read. A row in this state cannot be signed in to, whatever
    /// password is presented.</summary>
    Unknown = 0,

    /// <summary>An Argon2id PHC string, the only form <see cref="PasswordHasher.Hash"/> writes.</summary>
    Argon2id = 1,

    /// <summary>A bcrypt modular-crypt string, inherited from the Go service being replaced. Read
    /// only: it verifies, and a successful verification rewrites the row as
    /// <see cref="Argon2id"/>.</summary>
    Bcrypt = 2,
}

/// <summary>
/// Password hashing. <b>Writes Argon2id only; reads Argon2id and bcrypt.</b>
/// <para>
/// The asymmetry is the whole design. The Go service this replaces hashed with bcrypt, and
/// <c>uam.backend_users</c> holds 17 accounts whose passwords are all <c>$2a$10$</c> strings
/// (measured against the live database, 2026-09-03: 17 rows, 17 with a password, 17 bcrypt, 0
/// Argon2id). Without a read path for them, cutover day locks every existing operator out of the
/// back office with a 401 that is indistinguishable from a typo - the failure looks like "the new
/// service's password login is broken", not like a data migration that was never done.
/// </para>
/// <para>
/// <b>No algorithm column is needed for this, and none was ever the problem.</b> A PHC string and a
/// bcrypt modular-crypt string both begin with their own algorithm name, so the stored value
/// answers "which branch" by itself; <c>WHERE password_hash NOT LIKE '$argon2id$%'</c> answers
/// "which rows still need rewriting" for the same cost a column would. The consumer plane's
/// <c>identity.users.password_algo</c> exists and is harmless, but it is not what makes dispatch
/// possible - see <see cref="Identify"/>.
/// </para>
/// <para>
/// <b>Migration happens by being used.</b> This class cannot perform it: it holds no repository,
/// and rewriting a row from inside <see cref="Verify"/> would put a write on a read path that also
/// runs for wrong passwords and for accounts that do not exist. The rewrite belongs to the
/// sign-in flow, after a sign-in has actually succeeded - see
/// <c>BackOfficeSignInAppService.MigrateStoredPasswordAsync</c>. Callers ask
/// <see cref="Identify"/> whether the row they just verified needs it.
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
    /// <para>
    /// <b>They are also the yardstick the password door's timing equaliser is measured against</b>
    /// (<c>BackOfficePasswordTiming</c>), and the legacy bcrypt branch is now measured against them
    /// too. Changing them moves both - read that type's notes before touching these.
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

    /// <summary>The PHC prefix of the only algorithm this class writes.</summary>
    private const string Argon2idPrefix = "$argon2id$";

    /// <summary>
    /// The bcrypt revisions this class will verify against, and the complete list.
    /// <para>
    /// All three share one key schedule and differ only in how a long or non-ASCII password is
    /// fed to it, which is why a stored revision has to be honoured rather than normalized.
    /// <b><c>$2x$</c> is deliberately absent.</b> It exists to reproduce a known bug in
    /// <c>crypt_blowfish</c>'s handling of 8-bit characters; Go's <c>x/crypto/bcrypt</c>, which
    /// wrote every legacy row here, never emits it, and the live table contains only
    /// <c>$2a$</c> (measured: 17 of 17). Accepting it would mean verifying against a key schedule
    /// we know to be broken for the sake of rows that do not exist.
    /// </para>
    /// </summary>
    private static readonly string[] BcryptPrefixes = ["$2a$", "$2b$", "$2y$"];

    /// <summary>
    /// The exact length of a bcrypt modular-crypt string: 7 characters of prefix, 22 of salt, 31 of
    /// digest. It is not a range - the format has no variable-length form, and Go's
    /// <c>x/crypto/bcrypt</c> emits nothing else (measured: all 17 live rows are 60 characters).
    /// <para>
    /// Checking it here rather than letting the library discover it matters: <c>BCrypt.Verify</c>
    /// <b>throws</b> on a short string rather than returning false - measured, five different
    /// exception types across the malformed cases - and this method is on the path of every
    /// sign-in attempt.
    /// </para>
    /// </summary>
    private const int BcryptHashLength = 60;

    /// <summary>
    /// The highest bcrypt work factor <see cref="Verify"/> will honour. The same reasoning as
    /// <see cref="MaxMemoryKibibytes"/>, for the other cost model: a bcrypt row is an instruction
    /// to perform 2^cost key expansions, and the format's own ceiling is 31.
    /// <para>
    /// <b>Measured on this machine:</b> cost 10 (every legacy row) verifies in 49 ms, cost 12 in
    /// 196 ms. Cost 31 does not return - a probe left it running with no output and it had to be
    /// killed, which is what one stolen request thread per attempt looks like. Twelve is four times
    /// the work of the only cost the data actually contains, which leaves room for a legacy row
    /// written at a higher factor while keeping the worst case a fifth of a second.
    /// </para>
    /// <para>
    /// A row outside the bound reads as unverifiable, exactly like a damaged one: its owner cannot
    /// sign in, and the sign-in flow logs that the stored value is unreadable - which it can only
    /// do because <see cref="IsReadable"/>, not <see cref="Identify"/>, is what it asks. A value
    /// above this ceiling still names bcrypt, so the prefix alone would call it readable.
    /// </para>
    /// </summary>
    private const int MaxBcryptCost = 12;

    /// <summary>
    /// Which algorithm the stored string declares, from its own prefix and nothing else.
    /// <para>
    /// <b>This is not sniffing.</b> Both formats are self-describing: a PHC string's first field is
    /// its algorithm name and a bcrypt string's is its revision. Reading it off the value is the
    /// same answer a separate algorithm column would give, from a source that cannot drift out of
    /// step with the digest beside it.
    /// </para>
    /// <para>
    /// The two questions callers ask are both answered here, and that is why there is one method
    /// rather than two predicates: <see cref="StoredPasswordAlgorithms.Bcrypt"/> means "rewrite
    /// this row after a successful sign-in", and <see cref="StoredPasswordAlgorithms.Unknown"/>
    /// means "no password can ever verify against this row", which the sign-in flow has to log
    /// because <see cref="Verify"/> reports it as an ordinary wrong password.
    /// </para>
    /// <para>
    /// It answers <see cref="StoredPasswordAlgorithms.Unknown"/> for null and for empty, so a
    /// caller may hand it a nullable column straight from the database.
    /// </para>
    /// </summary>
    public static StoredPasswordAlgorithms Identify(string? encoded)
    {
        if (string.IsNullOrEmpty(encoded))
        {
            return StoredPasswordAlgorithms.Unknown;
        }

        if (encoded.StartsWith(Argon2idPrefix, StringComparison.Ordinal))
        {
            return StoredPasswordAlgorithms.Argon2id;
        }

        foreach (var prefix in BcryptPrefixes)
        {
            if (encoded.StartsWith(prefix, StringComparison.Ordinal))
            {
                return StoredPasswordAlgorithms.Bcrypt;
            }
        }

        return StoredPasswordAlgorithms.Unknown;
    }

    /// <summary>
    /// Whether any password could ever verify against this stored value - that is, whether the
    /// algorithm the value names can actually read the rest of it.
    /// <para>
    /// <b>This is a different question from <see cref="Identify"/>, and the gap between them was a
    /// silent lockout.</b> A 29-character <c>$2a$10$...</c>, a work factor of 13 and a
    /// <c>$argon2id$</c> string with an undecodable salt all name an algorithm this service has,
    /// so <see cref="Identify"/> answers with that algorithm - but nothing will ever verify against
    /// them. <see cref="Verify"/> reports them as an ordinary wrong password, which is the right
    /// answer to give a caller and a useless one to give an operator, so the sign-in flow logs
    /// whatever this method calls unreadable.
    /// </para>
    /// <para>
    /// It costs no derivation and no key expansion, deliberately: it runs on failed sign-in
    /// attempts, so spending a hash here would make "this row is damaged" measurable from outside.
    /// </para>
    /// </summary>
    public static bool IsReadable(string? encoded) => Identify(encoded) switch
    {
        StoredPasswordAlgorithms.Argon2id => TryParseArgon2id(encoded!, out _, out _, out _, out _, out _),
        StoredPasswordAlgorithms.Bcrypt => encoded!.Length == BcryptHashLength && TryReadBcryptCost(encoded, out _),
        _ => false,
    };

    /// <summary>
    /// Hashes a password into <c>$argon2id$v=19$m=...,t=...,p=...$salt$hash</c>, the format the
    /// reference implementation and every other Argon2 library reads. Storing the parameters
    /// beside the digest is what makes them changeable.
    /// <para>
    /// <b>There is no bcrypt counterpart and there must not be one.</b> bcrypt is read-only here:
    /// this is the only thing that writes a password, so migration is a one-way ratchet and the
    /// legacy set can only shrink.
    /// </para>
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
    /// Verifies a candidate against a stored password string, dispatching on the algorithm that
    /// string declares: Argon2id with the parameters recorded in it, or legacy bcrypt with the work
    /// factor recorded in it. Anything else is unreadable and answers <c>false</c>.
    /// <para>
    /// <b>It must never throw, and that is a stronger requirement than it looks.</b> This runs on
    /// every sign-in attempt, including attempts against accounts with no password and against
    /// values nobody in this service wrote. A malformed stored value returns <c>false</c>: a row
    /// whose hash cannot be parsed is a row nobody can sign in to, and that is exactly the answer -
    /// turning it into a 500 would tell an attacker which accounts have damaged hashes. The bcrypt
    /// library does <i>not</i> share that discipline (it throws for a short string, a bad revision,
    /// an out-of-range cost and an empty value alike), so this method holds the bounds and the
    /// catch rather than trusting it.
    /// </para>
    /// <para>
    /// That silence has a cost, and it belongs to the caller: a damaged row is indistinguishable
    /// here from a wrong password, so the sign-in flow - not this class, which holds no logger
    /// precisely because it is pure computation - is where a stored value
    /// <see cref="IsReadable"/> rejects must be logged. Without that, "nobody can sign in to this
    /// account" is a fact only the user ever learns. <see cref="Identify"/> is the wrong question
    /// for that log: a damaged value still names its algorithm.
    /// </para>
    /// <para>
    /// <b>A true answer from the bcrypt branch is not the end of the story.</b> The caller is
    /// expected to ask <see cref="Identify"/> and rewrite the row; nothing here does it, because
    /// this method is also called on paths that must not write - see the note on the class.
    /// </para>
    /// </summary>
    public bool Verify(string password, string encoded)
    {
        // No stored hash can have come from an empty password, because Hash refuses to make one -
        // so there is nothing for it to match, and the derivations below would throw rather than
        // return false.
        if (string.IsNullOrEmpty(password))
        {
            return false;
        }

        return Identify(encoded) switch
        {
            StoredPasswordAlgorithms.Argon2id => VerifyArgon2id(password, encoded),
            StoredPasswordAlgorithms.Bcrypt => VerifyBcrypt(password, encoded),
            _ => false,
        };
    }

    private static bool VerifyArgon2id(string password, string encoded)
    {
        if (!TryParseArgon2id(encoded, out var salt, out var expected, out var memory, out var iterations, out var lanes))
        {
            return false;
        }

        var actual = Derive(password, salt, memory, iterations, lanes, expected.Length);

        // Constant time: a byte-by-byte comparison leaks how much of a guessed digest was right,
        // which over enough attempts is a digest oracle.
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>
    /// Reads everything an Argon2id PHC string carries except the derivation itself: the salt, the
    /// expected digest, and the three cost parameters bounded by their ceilings.
    /// <para>
    /// It is separate from the derivation because two callers need different halves of it.
    /// <see cref="VerifyArgon2id"/> needs the values; <see cref="IsReadable"/> needs only to know
    /// whether they are there, and must not spend a derivation to find out - that cost is exactly
    /// the signal a probe would be timing.
    /// </para>
    /// </summary>
    private static bool TryParseArgon2id(
        string encoded,
        out byte[] salt,
        out byte[] expected,
        out int memory,
        out int iterations,
        out int lanes)
    {
        salt = [];
        expected = [];
        memory = 0;
        iterations = 0;
        lanes = 0;

        var fields = encoded.Split('$');

        // ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash] - the leading empty field is
        // the string's own leading '$'. Field 1 is not re-checked: Identify matched it already.
        if (fields.Length != 6)
        {
            return false;
        }

        var parameters = fields[3].Split(',');
        if (parameters.Length != 3
            || !TryReadParameter(parameters[0], "m=", MaxMemoryKibibytes, out memory)
            || !TryReadParameter(parameters[1], "t=", MaxIterations, out iterations)
            || !TryReadParameter(parameters[2], "p=", MaxLanes, out lanes))
        {
            return false;
        }

        try
        {
            salt = Decode(fields[4]);
            expected = Decode(fields[5]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length != 0 && expected.Length != 0;
    }

    /// <summary>
    /// The legacy branch. It reads the shape itself before handing anything to the library, and
    /// then still catches: <c>BCrypt.Verify</c> throws on malformed input rather than answering
    /// false, and this is a path a wrong password reaches.
    /// <para>
    /// The four exception types are the ones a probe actually produced - <c>ArgumentException</c>
    /// (empty value, work factor below the library's floor of 4, and via
    /// <c>ArgumentOutOfRangeException</c> a truncated string), <c>IndexOutOfRangeException</c>
    /// (a bare <c>$2a$</c>), <c>FormatException</c> (undecodable salt bytes) and
    /// <c>SaltParseException</c> (unknown revision, cost out of range). They are enumerated
    /// rather than swallowed wholesale on purpose: anything outside this set is a library fault
    /// nobody has seen, and a 500 that gets noticed is a better outcome than a <c>false</c> that
    /// silently reads as a wrong password forever.
    /// </para>
    /// </summary>
    private static bool VerifyBcrypt(string password, string encoded)
    {
        // The same guards IsReadable applies, and the reason they are in both places is that these
        // two are the only callers and neither may assume the other ran.
        if (encoded.Length != BcryptHashLength || !TryReadBcryptCost(encoded, out _))
        {
            return false;
        }

        try
        {
            // enhancedEntropy stays false, which is the library's default and the only setting that
            // matches what wrote these rows: the "enhanced" mode pre-hashes the password with
            // SHA-384, so turning it on would fail every legacy row while looking like a wrong
            // password.
            return LegacyBcrypt.Verify(password, encoded);
        }
        catch (Exception ex) when (ex is ArgumentException
                                       or IndexOutOfRangeException
                                       or FormatException
                                       or LegacyBcryptSaltParseException)
        {
            return false;
        }
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

    /// <summary>
    /// Reads the two-digit work factor out of <c>$2a$10$...</c>, refusing anything above
    /// <see cref="MaxBcryptCost"/>. The format fixes its position, so there is nothing to search
    /// for: revision at 1-2, factor at 4-5, separators at 0, 3 and 6.
    /// <para>
    /// <see cref="NumberStyles.None"/> rather than the default, so a sign is not a digit: the
    /// default would read <c>$2a$+9$</c> as a work factor of 9 and pass a string the format does
    /// not allow through to the library.
    /// </para>
    /// <para>
    /// It indexes without bounds checks, which is safe only because its one caller has already
    /// established the length.
    /// </para>
    /// </summary>
    private static bool TryReadBcryptCost(string encoded, out int cost)
    {
        cost = 0;

        return encoded[6] == '$'
               && int.TryParse(encoded.AsSpan(4, 2), NumberStyles.None, CultureInfo.InvariantCulture, out cost)
               && cost > 0
               && cost <= MaxBcryptCost;
    }

    /// <summary>PHC uses unpadded standard base64, not base64url.</summary>
    private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=');

    private static byte[] Decode(string value) =>
        Convert.FromBase64String(value.PadRight(value.Length + ((4 - (value.Length % 4)) % 4), '='));
}
