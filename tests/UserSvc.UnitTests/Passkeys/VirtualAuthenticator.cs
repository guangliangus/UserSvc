using System.Buffers.Binary;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace UserSvc.UnitTests.Passkeys;

/// <summary>
/// A software authenticator: a real ES256 key pair that produces real, correctly signed WebAuthn
/// attestations and assertions.
/// <para>
/// <b>Every passkey test in this folder goes through this class rather than through a stubbed
/// verifier, because a stub cannot fail the way the thing being tested must fail.</b> The one
/// property this slice exists to provide - that a credential whose signature counter goes backwards
/// is refused - is a property of the signed bytes. A test that substituted the ceremony and
/// asserted "the fake said clone, the service answered 401" would pass just as happily against a
/// service that never verified anything at all.
/// </para>
/// <para>
/// It is deliberately controllable in the ways a hostile authenticator would be: the counter it
/// reports is a parameter, so a clone can be built by presenting a counter that has already been
/// seen; the origin it claims is a parameter, so a phishing origin can be tried; and the user
/// handle is a parameter, so one account's authenticator can be pointed at another's credential.
/// </para>
/// </summary>
internal sealed class VirtualAuthenticator : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>The credential id this authenticator answers for. Random per instance, as a real
    /// one is.</summary>
    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(32);

    /// <summary>The model identifier. <see cref="Guid.Empty"/> models the platform authenticators
    /// that decline to identify themselves.</summary>
    public Guid Aaguid { get; init; } = Guid.Parse("adce0002-35bc-c60a-648b-0b25f1f05503");

    /// <summary>Whether the credential reports itself as backup eligible (the BE flag).</summary>
    public bool BackupEligible { get; init; } = true;

    /// <summary>Whether the credential reports itself as backed up (the BS flag).</summary>
    public bool BackupState { get; init; } = true;

    /// <summary>The attestation for a registration ceremony, as the browser would send it.</summary>
    /// <param name="optionsJson">The creation options this service issued.</param>
    /// <param name="origin">What the client claims its origin is.</param>
    /// <param name="signCount">The counter the credential starts at. Zero for most real
    /// authenticators.</param>
    public string CreateAttestation(string optionsJson, string origin, uint signCount = 0)
    {
        var options = CredentialCreateOptions.FromJson(optionsJson);
        var clientDataJson = ClientData("webauthn.create", options.Challenge, origin);

        var attestedCredentialData = new AttestedCredentialData(
            Aaguid,
            CredentialId,
            new CredentialPublicKey(_key, COSE.Algorithm.ES256));

        var authenticatorData = new AuthenticatorData(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(options.Rp.Id)),
            Flags(attested: true),
            signCount,
            attestedCredentialData,
            null).ToByteArray();

        // Attestation format "none": no statement, no attestation key, no device identifier - what
        // every platform authenticator produces when the relying party does not ask for one, and
        // what this service asks for.
        var attestationObject = new CborMap
        {
            { "fmt", "none" },
            { "attStmt", new CborMap() },
            { "authData", authenticatorData },
        };

        return JsonSerializer.Serialize(new AuthenticatorAttestationRawResponse
        {
            Id = Base64Url.EncodeToString(CredentialId),
            RawId = CredentialId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = attestationObject.Encode(),
                ClientDataJson = clientDataJson,
                Transports = [AuthenticatorTransport.Internal],
            },
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
        });
    }

    /// <summary>The assertion for a login ceremony, as the browser would send it.</summary>
    /// <param name="optionsJson">The request options this service issued.</param>
    /// <param name="origin">What the client claims its origin is.</param>
    /// <param name="signCount">
    /// The counter to present. Raising it past the stored value is a normal login; repeating or
    /// lowering it is what a cloned authenticator does; leaving it at zero is what an authenticator
    /// that does not count does, on every login, legitimately.
    /// </param>
    /// <param name="userId">Whose user handle to present. Defaults to
    /// <paramref name="userId"/> = the account the credential belongs to.</param>
    /// <param name="tamperWithSignature">Corrupts one byte of the signature, to model an assertion
    /// that does not verify without changing anything else about it.</param>
    public string CreateAssertion(
        string optionsJson,
        string origin,
        uint signCount,
        int userId,
        bool tamperWithSignature = false)
    {
        var options = AssertionOptions.FromJson(optionsJson);
        var clientDataJson = ClientData("webauthn.get", options.Challenge, origin);

        var authenticatorData = new AuthenticatorData(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(options.RpId ?? string.Empty)),
            Flags(attested: false),
            signCount,
            null,
            null).ToByteArray();

        // What WebAuthn actually signs: the authenticator data followed by the hash of the client
        // data. The counter is inside the authenticator data, which is why a counter cannot be
        // edited in flight - it is covered by this signature.
        byte[] signedPayload = [.. authenticatorData, .. SHA256.HashData(clientDataJson)];
        var signature = _key.SignData(signedPayload, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        if (tamperWithSignature)
        {
            signature[^1] ^= 0xFF;
        }

        return JsonSerializer.Serialize(new AuthenticatorAssertionRawResponse
        {
            Id = Base64Url.EncodeToString(CredentialId),
            RawId = CredentialId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = authenticatorData,
                ClientDataJson = clientDataJson,
                Signature = signature,
                UserHandle = UserHandle(userId),
            },
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
        });
    }

    /// <summary>The eight-byte big-endian account handle this service derives from a user id.
    /// Duplicated here on purpose: a test that reused the production helper could not catch the
    /// production helper changing.</summary>
    public static byte[] UserHandle(int userId)
    {
        var handle = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(handle, (uint)userId);
        return handle;
    }

    public void Dispose() => _key.Dispose();

    private AuthenticatorFlags Flags(bool attested)
    {
        var flags = AuthenticatorFlags.UP | AuthenticatorFlags.UV;

        if (attested)
        {
            flags |= AuthenticatorFlags.AT;
        }

        if (BackupEligible)
        {
            flags |= AuthenticatorFlags.BE;
        }

        if (BackupState)
        {
            flags |= AuthenticatorFlags.BS;
        }

        return flags;
    }

    private static byte[] ClientData(string type, byte[] challenge, string origin) =>
        JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["type"] = type,
            ["challenge"] = Base64Url.EncodeToString(challenge),
            ["origin"] = origin,
            ["crossOrigin"] = false,
        });
}
