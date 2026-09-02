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
/// The OAuth <c>state</c> parameter, minted and verified without a single byte of server-side
/// storage: the value carries its own payload and an HMAC over it.
/// <para>
/// <b>Statelessness is the design, not a shortcut.</b> A state kept in Redis would make every
/// third-party sign-in depend on Redis being up, and would need a TTL, an eviction story and a
/// cleanup job for values that are read at most once. Signing instead means a replica that never
/// saw the request can still verify the redirect it receives.
/// </para>
/// <para>
/// <b>It also carries the LINE nonce</b>, which is the second reason it exists. LINE binds an
/// id_token to a nonce the client supplied; by deriving that nonce from the state we issued, the
/// server can later prove the token belongs to <i>this</i> flow without remembering anything. The
/// nonce is simply the state's own random component, handed to the client alongside it.
/// </para>
/// <para>
/// It is not a port: given a key it is arithmetic over a string, so tests use the real thing.
/// </para>
/// </summary>
public sealed class OAuthStateService(IOptions<SocialIdentityOptions> options, IClock clock)
{
    /// <summary>
    /// Domain separation. The same key signs the binding token, and without a distinct label a
    /// forger who obtained one signed blob could present it where the other is expected. It costs
    /// nothing and closes the whole class of confusion.
    /// </summary>
    private const string Context = "usersvc/oauth-state/v1";

    private readonly byte[] _key = Convert.FromHexString(options.Value.SigningKey);
    private readonly TimeSpan _lifetime = options.Value.StateLifetime;

    /// <summary>
    /// Issue a state for a flow that is about to leave for the provider.
    /// </summary>
    /// <param name="deviceId">
    /// The caller's device id, echoed back on return. Empty is legal and normal - a browser
    /// redirect carries no device header - and must not be an error, or web OAuth stops working.
    /// </param>
    public string Issue(string deviceId)
    {
        var issuedAt = clock.UtcNow;

        var payload = new StatePayload
        {
            Nonce = Guid.NewGuid().ToString("n"),
            DeviceId = deviceId ?? string.Empty,
            IssuedAt = issuedAt.ToUnixTimeSeconds(),
            ExpiresAt = (issuedAt + _lifetime).ToUnixTimeSeconds(),
        };

        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload, SocialJson.Default.StatePayload);

        return Base64Url.EncodeToString(payloadBytes) + "." + Base64Url.EncodeToString(Sign(payloadBytes));
    }

    /// <summary>The device id the state was issued for. Empty when it was issued without one.</summary>
    /// <exception cref="BadRequestException">The state is malformed, forged or expired.</exception>
    public string ReadDeviceId(string state) => Open(state).DeviceId;

    /// <summary>
    /// The nonce embedded in the state, which is what the client passes to the LINE SDK and what
    /// LINE is later asked to check the id_token against.
    /// </summary>
    /// <exception cref="BadRequestException">The state is malformed, forged or expired.</exception>
    public string ReadNonce(string state) => Open(state).Nonce;

    /// <summary>
    /// Parse, verify and un-expire in that order.
    /// <para>
    /// <b>Every failure answers the same sentence.</b> Telling a caller whether their state was
    /// mis-encoded, badly signed or merely stale would let them tune a forgery attempt one bit at a
    /// time, and none of the three changes what a legitimate client does next: start the flow
    /// again.
    /// </para>
    /// </summary>
    private StatePayload Open(string state)
    {
        if (string.IsNullOrEmpty(state))
        {
            throw Invalid();
        }

        var separator = state.IndexOf('.', StringComparison.Ordinal);
        if (separator <= 0 || separator == state.Length - 1)
        {
            throw Invalid();
        }

        byte[] payloadBytes;
        byte[] signature;

        try
        {
            payloadBytes = Base64Url.DecodeFromChars(state.AsSpan(0, separator));
            signature = Base64Url.DecodeFromChars(state.AsSpan(separator + 1));
        }
        catch (FormatException)
        {
            throw Invalid();
        }

        // Fixed-time comparison. A byte-by-byte one leaks how much of a forged signature was right,
        // which over enough attempts is the signature.
        if (!CryptographicOperations.FixedTimeEquals(signature, Sign(payloadBytes)))
        {
            throw Invalid();
        }

        StatePayload? payload;
        try
        {
            payload = JsonSerializer.Deserialize(payloadBytes, SocialJson.Default.StatePayload);
        }
        catch (JsonException)
        {
            throw Invalid();
        }

        if (payload is null || clock.UtcNow.ToUnixTimeSeconds() > payload.ExpiresAt)
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

        return HMACSHA256.HashData(_key, buffer);
    }

    private static BadRequestException Invalid() => new(
        ErrorCodes.InvalidState, "The sign-in state is invalid or has expired. Start the sign-in again.");

    /// <summary>
    /// The signed payload. Short property names because the whole thing travels in a query string
    /// through a third party's redirect, where length is a real constraint.
    /// </summary>
    internal sealed record StatePayload
    {
        [JsonPropertyName("n")]
        public string Nonce { get; init; } = string.Empty;

        [JsonPropertyName("d")]
        public string DeviceId { get; init; } = string.Empty;

        [JsonPropertyName("iat")]
        public long IssuedAt { get; init; }

        [JsonPropertyName("exp")]
        public long ExpiresAt { get; init; }
    }
}
