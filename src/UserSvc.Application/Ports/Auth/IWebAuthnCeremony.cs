namespace UserSvc.Application.Ports.Auth;

/// <summary>
/// The WebAuthn ceremony: challenge generation, attestation and assertion verification, and the
/// short-lived state that connects a ceremony's two halves.
/// <para>
/// <b>The challenge state is inside this port on purpose.</b> A ceremony is one operation that
/// happens over two HTTP requests, and what sits between them - the challenge, the allowed
/// credentials, which account asked - is not application state: it is the protocol's own working
/// memory, it is worthless to anyone but the verifier, and it must be destroyed the moment the
/// second half consumes it. Handing it to the application service would mean passing a challenge
/// through code that has no reason to see one, and would let a caller invent one. The adapter owns
/// it, hands back an opaque <c>flowId</c>, and refuses a flow it did not issue.
/// </para>
/// <para>
/// Nothing here is FIDO2-library-shaped. The records below are plain bytes and strings so the inner
/// rings never learn which library verifies the signature.
/// </para>
/// <para>
/// <b>Failures are the port's contract, not an implementation detail.</b> Implementations throw
/// <c>AppException</c> subtypes carrying the passkey error codes, and the split between them is
/// what the client branches on: an unusable or already-spent flow is 400
/// <c>PASSKEY_FLOW_EXPIRED</c>, an unparseable credential is 400 <c>PASSKEY_INVALID_REQUEST</c>, a
/// failed registration is 400 <c>PASSKEY_VERIFICATION_FAILED</c>, a failed assertion is
/// <b>401</b> <c>PASSKEY_VERIFICATION_FAILED</c>, and a regressed signature counter is
/// <b>401 <c>PASSKEY_POSSIBLE_CLONE</c></b> - never folded into the generic verification failure,
/// because it means something categorically different and someone has to be able to alert on it.
/// </para>
/// </summary>
public interface IWebAuthnCeremony
{
    /// <summary>
    /// Starts a registration and remembers the challenge.
    /// </summary>
    /// <param name="user">Who the credential will belong to. The user handle is derived from the
    /// account id by the adapter and is stable for the account's lifetime.</param>
    /// <param name="excludeCredentials">Credentials the account already holds, so an authenticator
    /// that is already enrolled declines instead of silently creating a second credential.</param>
    /// <param name="label">The label the client suggested at begin time, remembered with the flow
    /// so that a finish request that omits one still gets it.</param>
    /// <param name="cancellationToken">Cancels the ceremony-state write.</param>
    Task<WebAuthnCeremonyStart> BeginRegistrationAsync(
        WebAuthnUserEntity user,
        IReadOnlyList<WebAuthnCredentialReference> excludeCredentials,
        string? label,
        CancellationToken cancellationToken);

    /// <summary>
    /// Consumes the registration flow and verifies the attestation.
    /// <para>
    /// The flow is single-use and is spent whether or not verification then succeeds, so a client
    /// retrying a failed finish gets <c>PASSKEY_FLOW_EXPIRED</c> and must start again. That is
    /// deliberate: a challenge that survives a failed attempt is a challenge an attacker may keep
    /// trying against.
    /// </para>
    /// <para>
    /// <paramref name="userId"/> must be the account the flow was begun for; a mismatch is refused
    /// as an expired flow, which is what stops one user finishing another user's registration.
    /// </para>
    /// <para>
    /// Uniqueness of the credential id is <b>not</b> checked here. The application service checks
    /// it against its own table, because the library reports a duplicate as a generic verification
    /// failure and the client is owed the distinct "you already registered this key" answer.
    /// </para>
    /// </summary>
    Task<WebAuthnRegistration> CompleteRegistrationAsync(
        string flowId,
        int userId,
        string credentialJson,
        CancellationToken cancellationToken);

    /// <summary>
    /// Starts a login and remembers the challenge. An empty
    /// <see cref="WebAuthnLoginTarget.AllowCredentials"/> begins a discoverable ceremony, where the
    /// authenticator chooses the credential and the account is only learned at finish time.
    /// </summary>
    Task<WebAuthnCeremonyStart> BeginLoginAsync(WebAuthnLoginTarget target, CancellationToken cancellationToken);

    /// <summary>
    /// Consumes the login flow and parses the assertion, far enough to say <i>which</i> credential
    /// the client used - but verifies nothing yet, because verification needs the stored public key
    /// and only the caller can look that up.
    /// <para>
    /// Split from <see cref="CompleteLoginAsync"/> so that the decision the split enables - what to
    /// answer when the credential is unknown to us - stays in the application service, where the
    /// rest of the enumeration-sensitive answers already live.
    /// </para>
    /// </summary>
    Task<WebAuthnAssertionRequest> TakeAssertionAsync(
        string flowId,
        string credentialJson,
        CancellationToken cancellationToken);

    /// <summary>
    /// Verifies the assertion against the credential we hold, including the signature-counter
    /// regression check.
    /// </summary>
    Task<WebAuthnAssertion> CompleteLoginAsync(
        WebAuthnAssertionRequest request,
        WebAuthnStoredCredential credential,
        CancellationToken cancellationToken);
}

/// <summary>The two halves of a begin response: the opaque flow handle the client returns to us,
/// and the WebAuthn options object it hands to the browser verbatim.</summary>
/// <param name="FlowId">Opaque; the client echoes it back and nothing else may interpret it.</param>
/// <param name="OptionsJson">A serialized <c>PublicKeyCredentialCreationOptions</c> or
/// <c>PublicKeyCredentialRequestOptions</c>, binary members already base64url-encoded.</param>
public sealed record WebAuthnCeremonyStart(string FlowId, string OptionsJson);

/// <summary>The account a credential is being created for, in WebAuthn's terms.</summary>
/// <param name="UserId">The account id. The adapter derives the stable 8-byte user handle from it.</param>
/// <param name="Name">The account name shown in the authenticator's credential picker.</param>
/// <param name="DisplayName">The friendly name shown beside it.</param>
public sealed record WebAuthnUserEntity(int UserId, string Name, string DisplayName);

/// <summary>A credential the authenticator may be told about: to exclude at registration, or to
/// allow at login.</summary>
public sealed record WebAuthnCredentialReference(byte[] CredentialId, IReadOnlyList<string> Transports);

/// <summary>
/// What a login ceremony is scoped to.
/// </summary>
/// <param name="UserId">
/// The account, when the client named an identifier we recognised, or null for a discoverable
/// login. Remembered with the flow so the finish half can insist the credential presented belongs
/// to the account the challenge was issued for.
/// </param>
/// <param name="AllowCredentials">Empty for a discoverable login.</param>
public sealed record WebAuthnLoginTarget(int? UserId, IReadOnlyList<WebAuthnCredentialReference> AllowCredentials);

/// <summary>A verified new credential, ready to be stored.</summary>
/// <param name="CredentialId">Raw credential id.</param>
/// <param name="PublicKey">COSE-encoded public key.</param>
/// <param name="SignCount">The counter the authenticator started at; commonly 0.</param>
/// <param name="Aaguid">The 16-byte authenticator model id, or null when it was all zeroes.</param>
/// <param name="Transports">Client-reported transports, lower-case WebAuthn spellings.</param>
/// <param name="AttestationFormat">The attestation statement format: <c>none</c>, <c>packed</c>, …</param>
/// <param name="BackupEligible">The BE flag, fixed for the credential's lifetime.</param>
/// <param name="BackupState">The BS flag as of this ceremony.</param>
/// <param name="Label">The label carried on the flow from the begin request, if any.</param>
public sealed record WebAuthnRegistration(
    byte[] CredentialId,
    byte[] PublicKey,
    long SignCount,
    byte[]? Aaguid,
    IReadOnlyList<string> Transports,
    string AttestationFormat,
    bool BackupEligible,
    bool BackupState,
    string? Label);

/// <summary>
/// A parsed, not yet verified assertion together with the consumed flow it belongs to.
/// </summary>
/// <param name="CeremonyState">
/// Opaque state the adapter needs to finish the verification. It is carried through the
/// application service untouched; nothing outside the adapter may read or construct it.
/// </param>
/// <param name="UserId">The account the flow was begun for, or null for a discoverable login.</param>
/// <param name="CredentialId">Which credential the client says it used.</param>
/// <param name="CredentialJson">The raw assertion, still to be verified.</param>
public sealed record WebAuthnAssertionRequest(
    string CeremonyState,
    int? UserId,
    byte[] CredentialId,
    string CredentialJson);

/// <summary>What the verifier needs to know about the credential we stored.</summary>
public sealed record WebAuthnStoredCredential(byte[] CredentialId, byte[] PublicKey, long SignCount, int UserId);

/// <summary>A verified assertion.</summary>
/// <param name="CredentialId">The credential that signed.</param>
/// <param name="SignCount">The counter the authenticator presented, already checked against the
/// stored one.</param>
/// <param name="BackupState">The BS flag as of this assertion; it changes over a credential's life
/// and is written back on every login.</param>
public sealed record WebAuthnAssertion(byte[] CredentialId, long SignCount, bool BackupState);
