using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;

namespace UserSvc.Application.Features.SocialIdentity;

/// <summary>
/// The short-lived token that carries a pending Firebase binding across the consent screen.
/// <para>
/// The situation it exists for: someone signs in with Google, the address on that Google account
/// already belongs to an account here, and attaching the two is a decision only the human can make.
/// The server has to remember the proposal while the user reads a dialog - and it does so by
/// handing the proposal to the client, signed, rather than by keeping it.
/// </para>
/// <para>
/// <b>Everything the confirmation needs is inside the token, and that is deliberate.</b> The
/// confirm endpoint re-derives the target account, the Firebase uid and the provider from the
/// signature rather than trusting anything the client sends alongside - so a client cannot swap the
/// target account between the proposal and the confirmation, which is exactly the attack a naive
/// "pass the user id back" design invites.
/// </para>
/// <para>
/// It is signed with the same key as the OAuth state but under a different domain-separation
/// label, so neither can ever be presented where the other is expected.
/// </para>
/// </summary>
public sealed class SocialBindingTokenService(IOptions<SocialIdentityOptions> options, IClock clock)
{
    private const string Context = "usersvc/firebase-binding/v1";

    // Read at the point of use, NOT in a field initializer - see the identical note in
    // OAuthStateService. IOptions<T>.Value runs DataAnnotations validation, so an eager read made
    // this type throw merely by being constructed, and it is a constructor dependency of
    // SocialIdentityAppService, so it took down unbind too. Lazy defers it; Value caches after first.
    private readonly Lazy<byte[]> _key = new(() => Convert.FromHexString(options.Value.SigningKey));

    private TimeSpan Lifetime => options.Value.BindingTokenLifetime;

    public string Issue(FirebaseBindingProposal proposal)
    {
        ArgumentNullException.ThrowIfNull(proposal);

        var payload = proposal with { ExpiresAt = (clock.UtcNow + Lifetime).ToUnixTimeSeconds() };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, SocialJson.Default.FirebaseBindingProposal);

        return Base64Url.EncodeToString(bytes) + "." + Base64Url.EncodeToString(Sign(bytes));
    }

    /// <exception cref="UnauthorizedException">
    /// The token is malformed, forged or expired. 401 rather than 400: the token <i>is</i> the
    /// credential for this operation, so an unusable one means "authenticate again", which here
    /// means "start the Firebase sign-in over".
    /// </exception>
    public FirebaseBindingProposal Open(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            throw Invalid();
        }

        var separator = token.IndexOf('.', StringComparison.Ordinal);
        if (separator <= 0 || separator == token.Length - 1)
        {
            throw Invalid();
        }

        byte[] payloadBytes;
        byte[] signature;

        try
        {
            payloadBytes = Base64Url.DecodeFromChars(token.AsSpan(0, separator));
            signature = Base64Url.DecodeFromChars(token.AsSpan(separator + 1));
        }
        catch (FormatException)
        {
            throw Invalid();
        }

        if (!CryptographicOperations.FixedTimeEquals(signature, Sign(payloadBytes)))
        {
            throw Invalid();
        }

        FirebaseBindingProposal? payload;
        try
        {
            payload = JsonSerializer.Deserialize(payloadBytes, SocialJson.Default.FirebaseBindingProposal);
        }
        catch (JsonException)
        {
            throw Invalid();
        }

        if (payload is null || payload.TargetUserId <= 0 || clock.UtcNow.ToUnixTimeSeconds() > payload.ExpiresAt)
        {
            throw Invalid();
        }

        return payload;
    }

    private byte[] Sign(byte[] payload)
    {
        var buffer = new byte[Context.Length + payload.Length];
        Encoding.ASCII.GetBytes(Context, buffer);
        payload.CopyTo(buffer, Context.Length);

        return HMACSHA256.HashData(_key.Value, buffer);
    }

    private static UnauthorizedException Invalid() => new(
        ErrorCodes.BindingTokenInvalid,
        "The binding confirmation has expired or is not valid. Sign in with the provider again.");
}

/// <summary>
/// A pending "attach this Firebase account to that existing account" decision, in the exact shape
/// it travels in.
/// </summary>
/// <param name="FirebaseUid">The uid the token verified to.</param>
/// <param name="Provider">The sign-in provider the uid came from.</param>
/// <param name="ProviderUid">The third-party account's own subject; the durable half of the key.</param>
/// <param name="TargetUserId">The existing account the identity would be attached to.</param>
/// <param name="EmailMasked">
/// The masked form of the address that matched, purely so the consent screen can say which account
/// it means. <b>Masked and not the address itself</b>: the token is handed to a client that has
/// only proved control of the Firebase account, and if the two are the same address it already
/// knows it.
/// </param>
/// <param name="Name">Display name from the Firebase profile, recorded on the identity when created.</param>
public sealed record FirebaseBindingProposal(
    [property: JsonPropertyName("uid")] string FirebaseUid,
    [property: JsonPropertyName("p")] string Provider,
    [property: JsonPropertyName("puid")] string ProviderUid,
    [property: JsonPropertyName("uid_target")] int TargetUserId,
    [property: JsonPropertyName("em")] string EmailMasked,
    [property: JsonPropertyName("n")] string Name)
{
    /// <summary>Unix seconds. Set by <see cref="SocialBindingTokenService.Issue"/>; any value a
    /// caller supplies is overwritten.</summary>
    [JsonPropertyName("exp")]
    public long ExpiresAt { get; init; }
}
