namespace UserSvc.Application.Ports.Platform;

/// <summary>
/// A shared "this one has already been used" marker, claimed atomically and exactly once.
/// <para>
/// It exists for credentials that are self-contained and therefore not remembered anywhere - a
/// signed sign-in ticket, say. Such a credential is verifiable by any replica with the key and no
/// state at all, which is what makes it cheap, and it is also what makes it replayable for as long
/// as it is valid. This is the smallest amount of state that fixes that: one key per credential,
/// living exactly as long as the credential does.
/// </para>
/// <para>
/// <b>It fails CLOSED, and the revocation store beside it fails OPEN. That difference is
/// deliberate, and a future reader will otherwise "fix" the inconsistency.</b> The test in
/// docs/architecture.md is what a failure falls back to.
/// <list type="bullet">
/// <item><description>
/// <c>ISessionRevocationStore</c>'s read is an <i>extra</i> check on top of a token that has
/// already passed full signature validation, and the ten-minute access-token lifetime is the
/// backstop underneath it. Allowing on failure loses a few minutes of a revocation that is
/// authoritative in PostgreSQL anyway, whereas refusing on failure would take every authenticated
/// request in the service down with one Redis blip.
/// </description></item>
/// <item><description>
/// This marker <i>is</i> the check. There is no second place that knows whether a ticket has been
/// redeemed, so allowing on failure does not degrade the guarantee, it removes it: during any
/// Redis trouble every intercepted ticket becomes replayable again, and nothing in the response
/// or the trail would say the guarantee had lapsed. Refusing costs a signed-in operator one
/// "sign in again", which is a two-minute-old credential they still have the password for.
/// </description></item>
/// </list>
/// The same asymmetry the failure-semantics table already records for reading versus writing the
/// revocation set: read has a backstop, write has none.
/// </para>
/// <para>
/// <b>It has to be shared state, not per-process.</b> A ticket is minted by whichever pod served
/// the sign-in and redeemed by whichever pod serves the token request a moment later. An in-memory
/// marker would refuse a replay only on the pod that happened to mint it, so behind a load balancer
/// a replay would succeed roughly (n-1)/n of the time - which presents as "single use works
/// sometimes", the worst possible shape for a security control.
/// </para>
/// </summary>
public interface ISingleUseMarkerStore
{
    /// <summary>
    /// Claims <paramref name="id"/> within <paramref name="purpose"/>, atomically.
    /// </summary>
    /// <param name="purpose">
    /// What kind of thing is being consumed, as a stable slug - <c>back-office-sign-in-ticket</c>.
    /// Two purposes never share a key space, so an id that happens to collide across two kinds of
    /// credential cannot consume the other one.
    /// </param>
    /// <param name="id">
    /// The credential's own unique id. It must be unpredictable and unique per issue: a guessable
    /// one would let an attacker burn a ticket that has not been issued yet, which is a
    /// denial-of-service against a sign-in rather than a leak, but still free.
    /// </param>
    /// <param name="timeToLive">
    /// How long the marker must outlive the credential. <b>Never shorter than the credential's own
    /// lifetime</b>, or a replay lands in the gap between the marker expiring and the credential
    /// expiring - and that gap is precisely where an attacker with a captured credential is waiting.
    /// The TTL is what makes the key space bounded and self-cleaning, the same property the
    /// revocation set relies on.
    /// </param>
    /// <param name="cancellationToken">
    /// Honoured before the command is issued; the command itself may not be cancellable.
    /// </param>
    /// <returns>
    /// <c>true</c> when this call is the one that claimed it, <c>false</c> when it was already
    /// claimed. A caller must treat <c>false</c> as a refusal.
    /// </returns>
    /// <exception cref="Errors.AppException">
    /// The store could not be reached, so nothing can be said about whether this credential has
    /// been used. Implementations <b>throw rather than return <c>false</c></b>: both outcomes
    /// refuse the request, but they are different events and must not read the same in the log or
    /// on the wire. "Already used" is an attacker replaying a credential; "cannot tell" is our own
    /// infrastructure being down, which is a 5xx and an operator's problem rather than the caller's.
    /// </exception>
    Task<bool> TryClaimAsync(
        string purpose,
        string id,
        TimeSpan timeToLive,
        CancellationToken cancellationToken);
}
