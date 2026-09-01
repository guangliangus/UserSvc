using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace UserSvc.Application.Security;

/// <summary>
/// Blind index plus envelope encryption (decision 13): one HMAC column for exact lookups, one
/// AES-256-GCM column for retrieving the value.
/// <para>
/// <b>This is not a port.</b> Given a key it is pure computation — it crosses no process boundary
/// and unit tests can use the real thing. Putting it in <c>Ports/</c> would be the over-engineered
/// choice; <c>Ports/</c> holds I/O and nothing else.
/// </para>
/// </summary>
public sealed class IdentifierProtector
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly byte[] _pepper;
    private readonly byte[] _dataKey;

    public IdentifierProtector(IOptions<IdentifierProtectionOptions> options)
    {
        var value = options.Value;
        _pepper = Convert.FromHexString(value.Pepper);
        _dataKey = Convert.FromBase64String(value.DataKey);
        KeyVersion = value.KeyVersion;

        if (_dataKey.Length != 32)
        {
            throw new InvalidOperationException(
                $"IdentifierProtection:DataKey must decode to 32 bytes, got {_dataKey.Length}.");
        }
    }

    /// <summary>Current DEK version, written to the entity's <c>*_key_version</c> column.</summary>
    public string KeyVersion { get; }

    /// <summary>Blind index: a deterministic hash that carries both the unique index and exact lookups.</summary>
    public string Hash(string plaintext)
    {
        var bytes = HMACSHA256.HashData(_pepper, Encoding.UTF8.GetBytes(plaintext));
        return Convert.ToHexStringLower(bytes);
    }

    /// <summary>Encrypts to base64 (unpadded) of <c>nonce‖ciphertext‖tag</c>.</summary>
    public string Encrypt(string plaintext)
    {
        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var payload = new byte[NonceSize + plainBytes.Length + TagSize];

        var nonce = payload.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(_dataKey, TagSize);
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

        using var aes = new AesGcm(_dataKey, TagSize);
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
}
