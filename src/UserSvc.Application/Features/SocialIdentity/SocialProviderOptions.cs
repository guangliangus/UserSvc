using System.ComponentModel.DataAnnotations;

namespace UserSvc.Application.Features.SocialIdentity;

/// <summary>
/// WeChat web OAuth credentials.
/// <para>
/// <b><see cref="AppId"/> and <see cref="AppSecret"/> are <see cref="RequiredAttribute"/> with no
/// default anywhere.</b> A deployment that routes these endpoints without credentials refuses to
/// boot, which is the loud failure; the quiet one it replaces is a WeChat sign-in that answers
/// "invalid code" to every user because the secret was empty, and looks like WeChat's fault.
/// </para>
/// </summary>
public sealed class WechatOptions : SocialProviderEndpointOptions
{
    public const string SectionName = "Wechat";

    protected override string Section => SectionName;

    /// <summary>The WeChat Official Account AppID. Public - it travels in the authorization URL.</summary>
    [Required]
    public string AppId { get; init; } = string.Empty;

    /// <summary>The matching secret. Comes from Key Vault / ExternalSecrets, never from a file in the repository.</summary>
    [Required]
    public string AppSecret { get; init; } = string.Empty;

    /// <summary>Scope requested on the authorization URL. <c>snsapi_userinfo</c> asks the user; <c>snsapi_base</c> does not.</summary>
    [Required]
    public string Scope { get; init; } = "snsapi_userinfo";

    public override string BaseAddress { get; init; } = "https://api.weixin.qq.com/";
}

/// <summary>
/// The WeChat mini program, which is a <b>separate application</b> with separate credentials.
/// <para>
/// Reusing the web OAuth AppID here is the mistake worth naming, because it fails silently in the
/// worst possible direction: openids are issued per application, so the mini program would receive
/// openids from a different id space and every returning user would be resolved as a stranger,
/// creating one account per sign-in.
/// </para>
/// </summary>
public sealed class WechatMiniOptions : SocialProviderEndpointOptions
{
    public const string SectionName = "WechatMini";

    protected override string Section => SectionName;

    [Required]
    public string AppId { get; init; } = string.Empty;

    [Required]
    public string AppSecret { get; init; } = string.Empty;

    public override string BaseAddress { get; init; } = "https://api.weixin.qq.com/";

    /// <summary>
    /// How far ahead of WeChat's own expiry the cached access token is retired.
    /// <para>
    /// It exists so a token is never handed out with seconds left on it and then rejected mid
    /// flight by the very call it was fetched for. Five minutes is the original's value.
    /// </para>
    /// </summary>
    [Range(typeof(TimeSpan), "00:00:30", "00:30:00")]
    public TimeSpan AccessTokenExpirySkew { get; init; } = TimeSpan.FromMinutes(5);
}

/// <summary>LINE login channel settings.</summary>
public sealed class LineOptions : SocialProviderEndpointOptions
{
    public const string SectionName = "Line";

    protected override string Section => SectionName;

    /// <summary>
    /// The LINE channel id, which doubles as the OAuth client id and as the audience the id_token
    /// must name. <b>Required:</b> without it LINE would verify the signature but nothing would
    /// check that the token was minted for <i>this</i> channel, so a token issued to any other LINE
    /// app would sign its holder in here.
    /// </summary>
    [Required]
    public string ChannelId { get; init; } = string.Empty;

    /// <summary>Scope the client asks LINE for. <c>email</c> is what makes the address available at all.</summary>
    [Required]
    public string Scope { get; init; } = "openid profile email";

    public override string BaseAddress { get; init; } = "https://api.line.me/";
}

/// <summary>
/// Firebase project settings.
/// <para>
/// <b><see cref="ProjectId"/> alone is enough to verify an ID token</b> - verification is a
/// signature check against Google's public keys plus an audience and issuer check, and none of it
/// needs a credential. <see cref="CredentialsFile"/> buys one extra thing, described on it.
/// </para>
/// </summary>
public sealed class FirebaseOptions
{
    public const string SectionName = "Firebase";

    /// <summary>
    /// The Firebase project id. It is the token's audience and the tail of its issuer, so getting
    /// it wrong rejects every token with <c>FIREBASE_PROJECT_MISMATCH</c> - which is the intended
    /// outcome: a build pointed at the wrong project must not sign anyone in.
    /// </summary>
    [Required]
    public string ProjectId { get; init; } = string.Empty;

    /// <summary>
    /// Path to a service-account JSON file. <b>Optional, and the flow degrades rather than fails
    /// without it.</b>
    /// <para>
    /// What it unlocks is the Firebase user-record read that fills in a display name, an avatar or
    /// an address the token itself left empty - which happens for uids that were pre-created or
    /// linked across providers. Without the file, sign-in still works and is still fully verified;
    /// those accounts simply start with a default nickname. Making it required would take the
    /// entire Firebase sign-in offline to protect an enrichment step, which is the wrong trade.
    /// </para>
    /// </summary>
    public string CredentialsFile { get; init; } = string.Empty;
}

/// <summary>
/// The half of a provider's configuration that is about reaching it: one absolute base address,
/// validated the way <c>Notification:BaseAddress</c> is and for the same reason.
/// </summary>
public abstract class SocialProviderEndpointOptions : IValidatableObject
{
    /// <summary>
    /// Absolute base address, <b>trailing slash included</b>. Without the slash,
    /// <see cref="Uri"/> resolution drops the last path segment when the relative path is applied -
    /// no error anywhere, and the first symptom is a 404 from a host nobody suspects.
    /// </summary>
    [Required]
    public abstract string BaseAddress { get; init; }

    /// <summary>Section name, used only to make a validation message name the right key.</summary>
    protected abstract string Section { get; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!Uri.TryCreate(BaseAddress, UriKind.Absolute, out var parsed)
            || (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps))
        {
            yield return new ValidationResult(
                $"{Section}:{nameof(BaseAddress)} must be an absolute http or https URI.",
                [nameof(BaseAddress)]);
        }
        else if (!parsed.AbsolutePath.EndsWith('/'))
        {
            yield return new ValidationResult(
                $"{Section}:{nameof(BaseAddress)} must end with '/', or Uri resolution silently "
                + "drops its last path segment and every call goes to the wrong endpoint.",
                [nameof(BaseAddress)]);
        }
    }
}
