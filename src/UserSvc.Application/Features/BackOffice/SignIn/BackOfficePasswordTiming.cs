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
