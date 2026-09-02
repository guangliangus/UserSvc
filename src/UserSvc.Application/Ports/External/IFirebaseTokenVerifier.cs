namespace UserSvc.Application.Ports.External;

/// <summary>
/// Verification of a Firebase ID token - the credential a client gets after signing in with
/// Google, Apple or Facebook through the Firebase SDK.
/// <para>
/// It is a port because verification reaches Google for the rotating public keys that signed the
/// token, and because the profile enrichment reads the Firebase user record over the network.
/// </para>
/// <para>
/// <b>Every rejection is the implementation's to classify</b>, and it must be specific: the client
/// can retry a refreshed token after <c>FIREBASE_ID_TOKEN_EXPIRED</c> but must not bother after
/// <c>FIREBASE_ID_TOKEN_INVALID</c>, and <c>FIREBASE_PROJECT_MISMATCH</c> means a build was pointed
/// at the wrong Firebase project - three different things for whoever is holding the pager.
/// </para>
/// </summary>
public interface IFirebaseTokenVerifier
{
    /// <exception cref="Errors.AppException">
    /// The token did not verify (401 with one of the <c>FIREBASE_ID_TOKEN_*</c> /
    /// <c>FIREBASE_PROJECT_MISMATCH</c> codes), this deployment has no usable Firebase
    /// configuration (500 <c>FIREBASE_CONFIG_UNAVAILABLE</c>), or the user-record read failed
    /// (502 <c>FIREBASE_USER_LOOKUP_FAILED</c>).
    /// </exception>
    Task<FirebaseIdentity> VerifyIdTokenAsync(string idToken, CancellationToken cancellationToken);
}

/// <summary>Everything a Firebase sign-in tells us about the person behind it.</summary>
/// <param name="Uid">
/// The Firebase uid. Stable for as long as the Firebase user record lives - but Firebase mints a
/// <b>new</b> one if that record is ever deleted and re-created for the same third-party account,
/// which is why <paramref name="ProviderUid"/> exists and why the sign-in path falls back to it.
/// </param>
/// <param name="Provider">
/// The <c>firebase.sign_in_provider</c> claim: <c>google.com</c>, <c>apple.com</c>,
/// <c>facebook.com</c>. Empty when the token carries no such claim.
/// </param>
/// <param name="ProviderUid">
/// The third-party account's own subject, taken from <c>firebase.identities[provider][0]</c>. The
/// provider keeps it forever, so it - not <paramref name="Uid"/> - is the durable key. Empty when
/// the claim is absent.
/// </param>
/// <param name="Email">
/// The address on the token, refreshed from the Firebase user record when one could be read. It is
/// reported as given: deciding whether it is a real, reusable address is
/// <c>FirebaseEmailRules.UsableEmail</c>'s job, not this one's.
/// </param>
/// <param name="EmailVerified">
/// The token's own <c>email_verified</c> claim and nothing else. <b>Never overwritten from the user
/// record</b>: the record describes the account's current state, while this describes what the
/// credential in hand actually attested to.
/// </param>
/// <param name="Name">Display name, from the token or the user record. Empty when neither has one.</param>
/// <param name="Picture">Avatar URL, same sources, same fallback.</param>
public sealed record FirebaseIdentity(
    string Uid,
    string Provider,
    string ProviderUid,
    string Email,
    bool EmailVerified,
    string Name,
    string Picture);
