using UserSvc.Application.Features.Registration;

namespace UserSvc.Application.Features.BackOffice.SignIn;

/// <summary>
/// Makes the password door take the same time whether or not the mailbox it was given exists.
/// <para>
/// <b>Measured, not theorised.</b> Against the live service, forty interleaved samples per path:
/// an unknown mailbox answered <c>401 INVALID_CREDENTIALS</c> in a median of 3.6 ms, a wrong
/// password against a real account in 52.3 ms, and an account with no local password in 6.0 ms.
/// The three bodies are byte-identical, so the response says nothing - and the clock said which of
/// the three it was, every time. That is an account-existence oracle on an anonymous endpoint, and
/// a fourteen-fold separation needs no statistics to read.
/// </para>
/// <para>
/// The fix is to spend the missing cost rather than to hide it: every path that refuses before
/// reaching a real Argon2id verify runs one against <see cref="DummyHash"/> instead. Hiding it -
/// padding the response to a fixed delay - would need the delay to exceed the slowest real verify
/// under load, which is a number nobody knows, and it would make every wrong password slower for
/// no gain.
/// </para>
/// <para>
/// <b>The legacy bcrypt branch adds a fourth cost, and it does not equalise.</b> A row still
/// carrying a <c>$2a$10$</c> hash from the Go service verifies with bcrypt, not Argon2id, and the
/// two are not the same price. Measured twice, and the two agree. In isolation, n=40 each:
/// Argon2id at <c>m=19456,t=2,p=1</c> has a median of 36.9 ms, bcrypt at cost 10 has 49.3 ms.
/// Over real HTTP against the running service, 30 interleaved samples per path after fifty warm-up
/// attempts, medians:
/// </para>
/// <list type="table">
/// <item><description>unknown mailbox - 43.0 ms</description></item>
/// <item><description>account with no local password - 45.6 ms</description></item>
/// <item><description>wrong password, Argon2id row - 45.4 ms</description></item>
/// <item><description>wrong password, <b>bcrypt row</b> - <b>57.6 ms</b></description></item>
/// </list>
/// <para>
/// <b>The three wave-7 paths are still equalised</b> - 2.6 ms apart, against the 48.7 ms spread
/// that made the original oracle obvious. The fourth is 12.5 ms above them, 1.27x, and its samples
/// do not overlap theirs.
/// </para>
/// <para>
/// <b>So account existence is readable again, for the legacy rows only, and this says so rather
/// than rounding it off.</b> The unknown-mailbox path is one of the equalised three, so an
/// unmigrated row costing more than it means "this address exists" is back on the clock for those
/// addresses - not merely "this address has not migrated". Three things bound it, and none of them
/// is a fix: the separation is a quarter of one verify rather than fourteen times it; the set is at
/// most the 17 rows the Go service left behind; and every one of them leaves the set permanently
/// the first time its owner signs in, because that sign-in rewrites the row. It closes itself,
/// which is the property that made this the better trade than 17 operators locked out.
/// </para>
/// <para>
/// <b>One measurement artefact worth knowing on cutover day.</b> The first readings of the bcrypt
/// path in a freshly started process were 95-100 ms, not 57 - roughly 2.0x, not 1.27x - because
/// tiered compilation had not yet promoted a code path that only a handful of requests had
/// reached. So the separation is at its widest exactly when the legacy set is at its largest: the
/// minutes after a deployment. Nothing here warms it, and the cheap fix if it ever matters is one
/// throwaway verify against a dummy bcrypt string at startup, which belongs in the host and not in
/// this type.
/// </para>
/// <para>
/// <b>It was left rather than padded, and the alternative was worse.</b> Nothing can equalise the
/// two: the cost of a row is fixed by the row, an extra Argon2id verify on the bcrypt path makes
/// it 86 ms instead of 49, and padding is the technique this type exists to avoid. The trade taken
/// is a 12.5 ms separation on at most 17 self-clearing addresses against 17 operators who cannot
/// sign in at all.
/// <c>ALegacyRowsRefusalStaysWithinOneVerifyOfTheEqualisedPaths</c> pins the ratio, so a future
/// change to the Argon2id constants that widens it fails the build instead of quietly restoring
/// the oracle.
/// </para>
/// </summary>
public static class BackOfficePasswordTiming
{
    /// <summary>
    /// The hash the not-found paths verify against.
    /// <para>
    /// <b>Its parameters are this service's parameters</b> - <c>m=19456,t=2,p=1</c>, a 16-byte salt
    /// and a 32-byte tag, exactly what <see cref="PasswordHasher.Hash"/> writes. That is the whole
    /// point: <see cref="PasswordHasher.Verify"/> derives with the parameters found in the stored
    /// string, so a dummy with cheaper ones would cost less than a real verify and the oracle would
    /// simply come back quieter. <c>DummyHashCarriesTheProductionParameters</c> pins this against a
    /// freshly produced real hash, so the day the constants are raised the test fails instead of
    /// the property.
    /// </para>
    /// <para>
    /// <b>The tag is 32 random bytes, not the digest of a password.</b> Nobody - including whoever
    /// wrote this line - holds a preimage, so there is no value of <c>password</c> that makes the
    /// comparison return true. A "known dummy password" would be a real credential for every
    /// address that does not exist.
    /// </para>
    /// </summary>
    public const string DummyHash =
        "$argon2id$v=19$m=19456,t=2,p=1$iu41WM4fiofspiDcgWaw9g$lvi0+axu9fj+cEqrLWshQzet+EckTU0Zivhq+8fm0OA";

    /// <summary>
    /// Where the discarded answer goes. It exists so that the verify cannot be optimised away:
    /// a call whose only result is dropped is exactly the shape a compiler is allowed to remove,
    /// and this whole type is that call.
    /// </summary>
    private static bool _discarded;

    /// <summary>
    /// Burns one Argon2id verification and throws the answer away.
    /// <para>
    /// <b>Call it only on a path that will not reach a real verify.</b> Calling it before one would
    /// double the cost of every genuine sign-in attempt - two verifies per request, one of them
    /// pointless - and Argon2id is 19 MiB of resident memory per concurrent derivation, so the
    /// waste is in the container's memory limit and not only in the latency.
    /// </para>
    /// <para>
    /// <b>An empty password costs nothing here and nothing on the real path either</b>, because
    /// <see cref="PasswordHasher.Verify"/> refuses one before deriving. The two paths therefore
    /// still agree, which is the property this type is about - and the request validator refuses an
    /// empty password long before either.
    /// </para>
    /// <para>
    /// <b><see cref="DummyHash"/> stays an Argon2id string even though the door can now read
    /// bcrypt.</b> It has to match the cost of the branch a real account is most likely to take,
    /// and that is Argon2id for every account this service wrote and for every legacy account after
    /// its first sign-in. A bcrypt dummy would equalise against a set that is designed to empty
    /// itself.
    /// </para>
    /// </summary>
    public static void SpendVerifyCost(PasswordHasher hasher, string password)
    {
        ArgumentNullException.ThrowIfNull(hasher);

        // Volatile, so the store is a real store. Without it the JIT would be entitled to notice
        // that nothing ever reads the field, drop the assignment, then drop the call that produced
        // it - and the timing oracle would come back with no source change to point at.
        Volatile.Write(ref _discarded, hasher.Verify(password ?? string.Empty, DummyHash));
    }
}
