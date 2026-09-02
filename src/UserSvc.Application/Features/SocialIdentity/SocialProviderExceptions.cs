using UserSvc.Application.Errors;

namespace UserSvc.Application.Features.SocialIdentity;

/// <summary>
/// WeChat answered and refused: a code that was already redeemed, one that expired, one minted for
/// a different AppID, or a 200 response carrying no openid.
/// <para>
/// <b>It is a distinct type rather than a plain <see cref="BadRequestException"/> because the error
/// code depends on the flow, not on the adapter.</b> The same refusal is
/// <c>WECHAT_LOGIN_FAILED</c> on the sign-in path and <c>BIND_FAILED</c> on the bind path, and the
/// adapter has no idea which one it is serving. The code carried here is the sign-in one, so an
/// unhandled escape still says something true.
/// </para>
/// <para>
/// The distinction that matters is against the <i>other</i> failure: a WeChat that could not be
/// reached is an <see cref="UpstreamException"/> (502) and never this. Collapsing the two would
/// tell a user their login code was bad during a WeChat outage.
/// </para>
/// </summary>
public sealed class WechatRejectedException(string message, Exception? innerException = null)
    : AppException(ErrorCodes.WechatLoginFailed, message, 400, innerException);

/// <summary>
/// LINE would not vouch for the id_token. Unlike WeChat, this deliberately covers transport and
/// parse failures too: the verification happens <i>at LINE</i>, so "we could not ask" and "LINE
/// said no" both leave us holding an unverified token, and treating the first as an upstream
/// outage would mean answering 502 to a client that presented a forged token during one.
/// </summary>
public sealed class LineRejectedException(string message, Exception? innerException = null)
    : AppException(ErrorCodes.LineLoginFailed, message, 400, innerException);
