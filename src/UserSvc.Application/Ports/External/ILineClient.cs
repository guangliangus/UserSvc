namespace UserSvc.Application.Ports.External;

/// <summary>
/// LINE OpenID: hand the client's id_token to LINE and let LINE tell us who it belongs to.
/// <para>
/// <b>The verification is deliberately server-side at LINE rather than local.</b> LINE's
/// <c>/oauth2/v2.1/verify</c> endpoint checks the signature, the expiry, the audience and the nonce
/// in one call, which means this service holds no LINE public keys and cannot drift out of date
/// with LINE's rotation schedule. The cost is one network hop on every sign-in, and it is worth
/// paying.
/// </para>
/// <para>
/// The nonce is what binds the token to a state this server issued minutes ago. Passing it is not
/// optional decoration: without it an id_token captured from another session replays cleanly.
/// </para>
/// </summary>
public interface ILineClient
{
    /// <param name="cancellationToken">Cancels the call to LINE.</param>
    /// <param name="idToken">The OpenID Connect id_token from the LINE SDK.</param>
    /// <param name="nonce">
    /// The nonce carried inside the server-issued OAuth state. Empty skips the nonce check, which
    /// is a downgrade and should only happen where no state was issued in the first place.
    /// </param>
    /// <exception cref="Features.SocialIdentity.LineRejectedException">
    /// LINE refused the token, or answered something this service will not trust - a foreign
    /// issuer, an audience that is not our channel, a response with no subject. Transport and
    /// parse failures land here too: an unverifiable token is not a verified one, and the caller's
    /// answer is the same either way.
    /// </exception>
    Task<LineIdentity> VerifyIdTokenAsync(string idToken, string nonce, CancellationToken cancellationToken);
}

/// <summary>What a verified LINE id_token says about its holder.</summary>
/// <param name="Sub">
/// The LINE user id for this channel. The only field that is guaranteed present, and the one the
/// login identity is keyed on.
/// </param>
/// <param name="Email">
/// Present only when the channel requested the <c>email</c> scope and the user consented.
/// Empty otherwise - which is the common case, so nothing may depend on having it.
/// </param>
/// <param name="Name">Display name, empty when the profile scope was not granted.</param>
/// <param name="Picture">Avatar URL, same caveat.</param>
public sealed record LineIdentity(string Sub, string Email, string Name, string Picture);
