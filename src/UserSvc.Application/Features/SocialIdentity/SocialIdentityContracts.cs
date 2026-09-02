namespace UserSvc.Application.Features.SocialIdentity;

// ------------------------------------------------------------------ requests

/// <summary>What the client needs before it can send the user to WeChat's authorization page.</summary>
public sealed record WechatOAuthStartResponse
{
    /// <summary>The WeChat AppID the authorization URL must carry. Public by nature - it is in the URL.</summary>
    public required string AppId { get; init; }

    /// <summary>The signed state to hand back on return. Single flow, five minutes.</summary>
    public required string State { get; init; }

    /// <summary>The scope this deployment asks WeChat for, so the client does not hard-code it.</summary>
    public required string Scope { get; init; }
}

/// <summary>Same, for LINE - plus the nonce, which LINE has no equivalent of in the state itself.</summary>
public sealed record LineOAuthStartResponse
{
    public required string ChannelId { get; init; }

    public required string State { get; init; }

    /// <summary>
    /// Pass this to the LINE SDK. It is the state's own random component, so the backend can later
    /// prove the id_token belongs to this flow without having stored anything.
    /// </summary>
    public required string Nonce { get; init; }

    public required string Scope { get; init; }
}

/// <summary>A WeChat web OAuth callback, replayed to this service by the client.</summary>
public sealed record WechatSignInRequest
{
    /// <summary>The one-time authorization code from the WeChat redirect.</summary>
    public string Code { get; init; } = string.Empty;

    /// <summary>The state issued by <c>GET /auth/wechat/state</c>.</summary>
    public string State { get; init; } = string.Empty;
}

public sealed record WechatMiniSignInRequest
{
    /// <summary>The <c>js_code</c> from <c>wx.login</c>.</summary>
    public string Code { get; init; } = string.Empty;

    /// <summary>
    /// Optional code from <c>getPhoneNumber</c>. When present it is redeemed and used as a
    /// fallback way to recognise a returning user - and, for a brand-new one, bound as a phone
    /// identity so the account starts complete. Redeeming it is best effort throughout: a failure
    /// never blocks the sign-in.
    /// </summary>
    public string? PhoneCode { get; init; }
}

public sealed record LineSignInRequest
{
    public string IdToken { get; init; } = string.Empty;

    public string State { get; init; } = string.Empty;
}

public sealed record FirebaseSignInRequest
{
    public string FirebaseIdToken { get; init; } = string.Empty;

    /// <summary>
    /// Which provider the client believes it signed in with - <c>google.com</c>, <c>apple.com</c>,
    /// <c>facebook.com</c>. It is checked against the token's own <c>sign_in_provider</c> claim
    /// rather than trusted, so a mismatch is a refusal and not a correction.
    /// </summary>
    public string Provider { get; init; } = string.Empty;
}

public sealed record ConfirmFirebaseBindingRequest
{
    public string BindingToken { get; init; } = string.Empty;

    /// <summary>
    /// The user's answer. <see langword="false"/> is a legitimate value, not a missing one: it
    /// means "do not link these accounts", and the endpoint answers <c>canceled</c> without
    /// touching anything.
    /// </summary>
    public bool Confirm { get; init; }
}

// ------------------------------------------------------------------ responses

/// <summary>
/// The account a third-party credential resolved to.
/// <para>
/// <b>There is no token in here, and that is decision 10 rather than an omission.</b> OpenIddict
/// is the only thing in this service that mints credentials; sign-in resolves <i>who</i>, and
/// <c>/connect/token</c> issues the session. Returning a pair here would be a second token path,
/// and the two would eventually disagree about what a session is. Registration already works this
/// way.
/// </para>
/// </summary>
public sealed record SocialSignInResponse
{
    public required int UserId { get; init; }

    /// <summary>True when this credential created the account rather than finding it.</summary>
    public required bool IsNewUser { get; init; }

    /// <summary>
    /// The account has no active phone identity. The mobile clients use it to decide whether to
    /// show the "add your number" step straight after sign-in.
    /// </summary>
    public required bool NeedsBindPhone { get; init; }

    /// <summary>Every way this account can sign in, so the client can render the linked-accounts screen.</summary>
    public required IReadOnlyList<SocialIdentityResponse> Identities { get; init; }
}

/// <summary>One login identity, as much of it as an anonymous caller may see.</summary>
public sealed record SocialIdentityResponse
{
    public required string IdentityType { get; init; }

    /// <summary>
    /// Masked. The plaintext lives behind a token at <c>/user/profile</c>; see
    /// <see cref="SocialProfileText.Mask"/> for why this endpoint does not repeat it.
    /// </summary>
    public required string Identifier { get; init; }

    public required string Provider { get; init; }

    public required string ProviderUid { get; init; }

    public required string Status { get; init; }
}

/// <summary>
/// A Firebase sign-in, which has one more outcome than the others: the address on the third-party
/// account is already somebody's here, and only the human can say whether they are the same person.
/// </summary>
public sealed record FirebaseSignInResponse
{
    /// <summary>
    /// True when the client must show a consent screen and come back to
    /// <c>/auth/firebase/confirm-binding</c>. <see cref="Account"/> is null in that case - nothing
    /// has been created or linked yet.
    /// </summary>
    public required bool NeedsBindingConsent { get; init; }

    /// <summary>The resolved account, or null when consent is pending.</summary>
    public SocialSignInResponse? Account { get; init; }

    /// <summary>The signed proposal to hand back on confirmation. Null unless consent is pending.</summary>
    public string? BindingToken { get; init; }

    /// <summary>
    /// Masked address of the account the client is being asked to link into, so the consent screen
    /// can name it. Null unless consent is pending.
    /// </summary>
    public string? ExistingUserMaskedEmail { get; init; }

    /// <summary>Echoed on both branches, because the client correlates its pending sign-in by it.</summary>
    public required string FirebaseUid { get; init; }

    /// <summary>Echoed on both branches. Not omitted when empty: a client that reads it as "absent
    /// means unchanged" would carry the previous flow's provider into this one.</summary>
    public required string Provider { get; init; }

    public string? ProviderUid { get; init; }
}

/// <summary>The answer to a consent screen.</summary>
public sealed record ConfirmFirebaseBindingResponse
{
    /// <summary><c>confirmed</c> or <c>canceled</c>.</summary>
    public required string Status { get; init; }

    /// <summary>The account the identity was attached to. Null when the user declined.</summary>
    public SocialSignInResponse? Account { get; init; }
}

/// <summary>Statuses <see cref="ConfirmFirebaseBindingResponse.Status"/> can take.</summary>
public static class FirebaseBindingStatuses
{
    public const string Confirmed = "confirmed";
    public const string Canceled = "canceled";
}
