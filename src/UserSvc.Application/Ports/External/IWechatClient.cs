namespace UserSvc.Application.Ports.External;

/// <summary>
/// WeChat web OAuth: exchange the one-time <c>code</c> the browser came back with for the openid
/// that identifies this person inside this app. Network on the other side, so it is a port.
/// <para>
/// <b>The openid is app-scoped and the unionid is not.</b> One human signing in through the
/// website and through the mini program produces two different openids and, when both apps sit
/// under the same WeChat Open Platform account, one shared unionid. That asymmetry is the whole
/// reason the sign-in resolution has a second step; see
/// <c>SocialIdentityAppService.ResolveWechatAccountAsync</c>.
/// </para>
/// <para>
/// <b>Two failure shapes, and callers must be able to tell them apart.</b> An adapter throws
/// <c>WechatRejectedException</c> when WeChat itself answered and said no - a stale or replayed
/// code, a response with no openid - which is the caller's problem and a 400. Everything else
/// (connection refused, timeout, unparseable body) is an upstream fault and leaves as
/// <c>UpstreamException</c>, because nothing about the request was wrong.
/// </para>
/// </summary>
public interface IWechatClient
{
    /// <param name="code">The single-use authorization code from the WeChat redirect.</param>
    /// <param name="cancellationToken">Cancels the call to WeChat.</param>
    /// <exception cref="Features.SocialIdentity.WechatRejectedException">WeChat refused the code.</exception>
    /// <exception cref="Errors.UpstreamException">WeChat could not be reached or did not answer sensibly.</exception>
    Task<WechatCodeExchange> ExchangeCodeAsync(string code, CancellationToken cancellationToken);
}

/// <summary>
/// The WeChat mini program, which is a different application with different credentials even when
/// the same company owns both. <b>Its AppID must never be the web OAuth one</b> - openids are
/// issued per app, so reusing the credentials would silently file two people under one identity.
/// </summary>
public interface IWechatMiniClient
{
    /// <summary>
    /// <c>code2Session</c>: turn the mini program's <c>wx.login</c> js_code into an openid, the
    /// unionid when the app is bound to an Open Platform account, and the session key.
    /// </summary>
    /// <exception cref="Features.SocialIdentity.WechatRejectedException">WeChat refused the code.</exception>
    /// <exception cref="Errors.UpstreamException">WeChat could not be reached or did not answer sensibly.</exception>
    Task<WechatMiniCodeExchange> ExchangeSessionAsync(string jsCode, CancellationToken cancellationToken);

    /// <summary>
    /// Redeems the phone-number code that <c>getPhoneNumber</c> produced, returning the number in
    /// E.164 form (<c>+8613900000000</c>).
    /// <para>
    /// This call needs the mini program's global access token, which is rate limited and therefore
    /// cached; a token the cache believed was live can have been invalidated already, so an
    /// implementation is expected to drop the cache and retry exactly once on a token error. The
    /// caller treats the whole thing as best effort - see
    /// <c>SocialIdentityAppService.SignInWithWechatMiniAsync</c> - so a failure here must not be
    /// dressed up as anything a client should react to.
    /// </para>
    /// </summary>
    /// <returns>The number in E.164 form. Never empty: an empty answer is a failure.</returns>
    Task<string> GetPhoneNumberAsync(string phoneCode, CancellationToken cancellationToken);
}

/// <summary>Result of a web-OAuth code exchange.</summary>
/// <param name="OpenId">Stable per-app identifier for this person. Never empty on success.</param>
/// <param name="UnionId">
/// Cross-app identifier for the same person, or empty when the app is not bound to an Open
/// Platform account. Empty is normal, not an error.
/// </param>
public sealed record WechatCodeExchange(string OpenId, string UnionId);

/// <summary>Result of a mini-program <c>code2Session</c> exchange.</summary>
/// <param name="OpenId">Stable per-app identifier for this person. Never empty on success.</param>
/// <param name="UnionId">Cross-app identifier, or empty when the app is not bound to an Open Platform account.</param>
/// <param name="SessionKey">
/// The key WeChat issues for decrypting client-side payloads. This service does not decrypt
/// anything today - the phone number arrives through <see cref="IWechatMiniClient.GetPhoneNumberAsync"/>
/// instead - so it is carried but never stored. <b>It is a credential:</b> it must not be logged
/// and must not reach a response body.
/// </param>
public sealed record WechatMiniCodeExchange(string OpenId, string UnionId, string SessionKey);
