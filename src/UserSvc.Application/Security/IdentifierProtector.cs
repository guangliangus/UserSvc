using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;

namespace UserSvc.Application.Security;

/// <summary>
/// Blind index plus envelope encryption (decision 13): one HMAC column for exact lookups, one
/// AES-256-GCM column for retrieving the value.
/// <para>
/// <b>This is not a port.</b> Given a key it is pure computation — it crosses no process boundary
/// and unit tests can use the real thing. Putting it in <c>Ports/</c> would be the over-engineered
/// choice; <c>Ports/</c> holds I/O and nothing else.
/// </para>
/// <para>
/// <b>Constructing one never throws, and that is an availability requirement rather than a style
/// preference.</b> This type used to decode and length-check its key material in its constructor,
/// and it is a singleton that sits — by way of the back-office authorization snapshot provider — in
/// the dependency graph of a middleware which resolves that provider on <i>every</i> request,
/// before it has even looked at whether the caller is authenticated. Measured on a live host with
/// <c>IdentifierProtection__DataKey=QUJD</c> (three bytes): <c>GET /health/live</c>,
/// <c>GET /health/ready</c>, <c>GET /health/startup</c> and an anonymous
/// <c>GET /api/v1/back-office/supplier-links</c> all answered <c>500 INTERNAL_ERROR</c> with the
/// detail "The request could not be completed." — no probe could pass, no endpoint could answer,
/// and no response named the key. A liveness probe that fails over a bad secret makes Kubernetes
/// restart the pod forever for a fault no restart can repair.
/// </para>
/// <para>
/// So the key material is read behind a <see cref="Lazy{T}"/>: being constructed is total, and the
/// refusal lands on the first call that actually needs to hash or encrypt something. That refusal
/// is <see cref="ErrorCodes.NotConfigured"/> with the section named in the detail, which is the
/// contract every other missing secret in this service answers with (docs/architecture.md, "a
/// missing capability may only break itself"). <c>IdentifierProtectionHealthCheck</c> turns it back
/// into one honest signal for the platform: readiness reports unhealthy and names the setting,
/// while liveness — which carries no checks at all — stays healthy.
/// </para>
/// </summary>
public sealed class IdentifierProtector
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    /// <summary>AES-256, so the DEK has to decode to exactly this many bytes.</summary>
    private const int DataKeyBytes = 32;

    /// <summary>
    /// Every refusal this type produces opens with this sentence, so one search finds them in a log
    /// whichever of the settings was the broken one.
    /// </summary>
    private const string RefusalPrefix = "Identifier protection is not configured on this deployment: ";

    private readonly Lazy<KeyMaterial> _keys;

    public IdentifierProtector(IOptions<IdentifierProtectionOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Deferred, not merely wrapped: IOptions<T>.Value is where ValidateDataAnnotations runs,
        // and everything after it can reject the value it hands back. ExecutionAndPublication so
        // the decode happens once per process and a broken key keeps reporting the same refusal
        // rather than racing several threads through the same failure.
        _keys = new Lazy<KeyMaterial>(
            () => KeyMaterial.Read(options),
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <summary>Current DEK version, written to the entity's <c>*_key_version</c> column.</summary>
    public string KeyVersion => Keys.Version;

    private KeyMaterial Keys => _keys.Value;

    /// <summary>
    /// Forces the key material to be decoded and checked, throwing exactly what a real
    /// <see cref="Hash"/> or <see cref="Encrypt"/> call would throw on this deployment.
    /// <para>
    /// It exists for the readiness probe. A process whose DEK is malformed will never answer a
    /// request that touches an identifier correctly, so readiness has to say so — and it can only
    /// say so if something is willing to ask the question with no user request behind it. Nothing
    /// about this is test-only: it is the same code path, and after the first call it costs a field
    /// read.
    /// </para>
    /// </summary>
    public void EnsureUsable() => _ = Keys;

    /// <summary>Blind index: a deterministic hash that carries both the unique index and exact lookups.</summary>
    public string Hash(string plaintext)
    {
        var bytes = HMACSHA256.HashData(Keys.Pepper, Encoding.UTF8.GetBytes(plaintext));
        return Convert.ToHexStringLower(bytes);
    }

    /// <summary>Encrypts to base64 (unpadded) of <c>nonce‖ciphertext‖tag</c>.</summary>
    public string Encrypt(string plaintext)
    {
        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var payload = new byte[NonceSize + plainBytes.Length + TagSize];

        var nonce = payload.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(Keys.DataKey, TagSize);
        aes.Encrypt(
            nonce,
            plainBytes,
            payload.AsSpan(NonceSize, plainBytes.Length),
            payload.AsSpan(NonceSize + plainBytes.Length, TagSize));

        return Base64UrlNoPadding(payload);
    }

    public string Decrypt(string protectedValue)
    {
        var payload = FromBase64UrlNoPadding(protectedValue);
        if (payload.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("Protected value is too short to contain nonce and tag.");
        }

        var cipherLength = payload.Length - NonceSize - TagSize;
        var plainBytes = new byte[cipherLength];

        using var aes = new AesGcm(Keys.DataKey, TagSize);
        aes.Decrypt(
            payload.AsSpan(0, NonceSize),
            payload.AsSpan(NonceSize, cipherLength),
            payload.AsSpan(NonceSize + cipherLength, TagSize),
            plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }

    private static string Base64UrlNoPadding(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64UrlNoPadding(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        var padded = normalized.PadRight(normalized.Length + ((4 - (normalized.Length % 4)) % 4), '=');
        return Convert.FromBase64String(padded);
    }

    /// <summary>
    /// The decoded key material, produced once and only when something needs it.
    /// <para>
    /// One object rather than three fields, because the three values have to arrive together or not
    /// at all: a half-decoded protector that hashes but cannot encrypt would write rows nothing can
    /// read back.
    /// </para>
    /// </summary>
    private sealed class KeyMaterial(byte[] pepper, byte[] dataKey, string version)
    {
        public byte[] Pepper { get; } = pepper;

        public byte[] DataKey { get; } = dataKey;

        public string Version { get; } = version;

        public static KeyMaterial Read(IOptions<IdentifierProtectionOptions> options)
        {
            // An absent or empty section fails right here, as the OptionsValidationException that
            // AppExceptionHandler already maps to 500 NOT_CONFIGURED naming the offending members.
            // It is deliberately not re-wrapped: that path is the established one and its message
            // is already specific about which member is missing.
            var value = options.Value;

            byte[] pepper;

            try
            {
                pepper = Convert.FromHexString(value.Pepper);
            }
            catch (FormatException ex)
            {
                throw Unusable(
                    nameof(IdentifierProtectionOptions.Pepper),
                    "must be a hex-encoded HMAC pepper",
                    ex);
            }

            byte[] dataKey;

            try
            {
                dataKey = Convert.FromBase64String(value.DataKey);
            }
            catch (FormatException ex)
            {
                throw Unusable(
                    nameof(IdentifierProtectionOptions.DataKey),
                    $"must be a base64-encoded {DataKeyBytes}-byte key",
                    ex);
            }

            if (dataKey.Length != DataKeyBytes)
            {
                // The decoded length is in the message; the configured value never is. A usable key
                // is always 32 bytes, so this number only ever describes a key already known to be
                // broken - and it is the one fact that turns "the secret is wrong" into "somebody
                // put the wrong secret in this field".
                throw Unusable(
                    nameof(IdentifierProtectionOptions.DataKey),
                    $"must decode to {DataKeyBytes} bytes, and the configured value decodes to "
                    + $"{dataKey.Length}");
            }

            return new KeyMaterial(pepper, dataKey, value.KeyVersion);
        }

        /// <summary>
        /// 500 <see cref="ErrorCodes.NotConfigured"/> naming the setting and never quoting its
        /// value.
        /// <para>
        /// Not <c>INTERNAL_ERROR</c>, which sends an operator to read code when the answer is in
        /// the key store; and not the bare <see cref="InvalidOperationException"/> this used to
        /// throw, which reached the caller as a generic 500 whose body said only "The request could
        /// not be completed."
        /// </para>
        /// </summary>
        private static AppException Unusable(string setting, string requirement, Exception? cause = null) =>
            new(
                ErrorCodes.NotConfigured,
                $"{RefusalPrefix}{IdentifierProtectionOptions.SectionName}:{setting} {requirement}.",
                500,
                cause);
    }
}
