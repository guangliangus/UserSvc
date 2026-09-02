namespace UserSvc.Domain.Auth;

/// <summary>
/// One WebAuthn/FIDO2 credential belonging to one account. A user may hold several - a phone, a
/// laptop, a hardware key - and each one carries its own signature counter.
/// <para>
/// <b>This aggregate is rich rather than flat, and the signature counter is the only reason.</b>
/// Every other column here is CRUD, but the counter encodes the single security property a passkey
/// has over a password: the private key never leaves the authenticator, so a counter that goes
/// <i>backwards</i> is evidence that two devices are answering for one credential - that the key
/// was extracted and copied. Breaking that rule is a security incident, which is the test
/// <c>docs/architecture.md</c> sets for putting an invariant in the domain, so the rule lives in
/// <see cref="IndicatesClone"/> and the only way to move the counter is
/// <see cref="RecordAssertion"/>, which refuses to move it backwards.
/// </para>
/// </summary>
public sealed class UserPasskey
{
    /// <summary>The fallback label, used when neither the finish request nor the begin request
    /// named the credential.</summary>
    public const string DefaultName = "Passkey";

    /// <summary>Longest label the <c>name</c> column accepts. Enforced in code, not by the column
    /// type, so an over-long label is a 400 rather than a database error.</summary>
    public const int MaxNameLength = 100;

    public int Id { get; set; }

    public int UserId { get; set; }

    /// <summary>The WebAuthn credential id, raw bytes. Globally unique - it is what a discoverable
    /// login is located by, before any account is known.</summary>
    public byte[] CredentialId { get; set; } = [];

    /// <summary>The COSE-encoded public key. Everything an assertion is verified against.</summary>
    public byte[] PublicKey { get; set; } = [];

    /// <summary>
    /// The authenticator's signature counter as of the last accepted assertion.
    /// <para>
    /// <c>bigint</c> in the database though WebAuthn defines a 32-bit counter: the extra range
    /// costs nothing and a narrower column would have to be widened the first time an authenticator
    /// misbehaves. Zero means either "never used" or "this authenticator does not count" - see
    /// <see cref="IndicatesClone"/> for why those two cases are indistinguishable and must be.
    /// </para>
    /// </summary>
    public long SignCount { get; set; }

    /// <summary>The authenticator model identifier, 16 raw bytes, or null when the authenticator
    /// did not disclose one (an all-zero AAGUID, which most platform authenticators send).</summary>
    public byte[]? Aaguid { get; set; }

    /// <summary>The transports the client reported, as a JSON array of strings - for example
    /// <c>["internal","hybrid"]</c>. Stored verbatim so a future client hint we do not model yet
    /// survives the round trip.</summary>
    public string Transports { get; set; } = "[]";

    /// <summary>The attestation statement format the credential arrived with: <c>none</c>,
    /// <c>packed</c>, <c>apple</c>, and so on.</summary>
    public string AttestationType { get; set; } = "none";

    /// <summary>Whether the authenticator says this credential may be backed up (the BE flag).
    /// Fixed at registration - the specification forbids it changing.</summary>
    public bool BackupEligible { get; set; }

    /// <summary>Whether the credential is currently backed up (the BS flag). Unlike
    /// <see cref="BackupEligible"/> this one moves, so every accepted assertion rewrites it.</summary>
    public bool BackupState { get; set; }

    /// <summary>The user-visible label. Nullable in the database because the Go service left it
    /// unset on rows created before labels existed.</summary>
    public string? Name { get; set; }

    public DateTimeOffset? LastUsedAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public string? CreatedBy { get; set; }

    public string? UpdatedBy { get; set; }

    /// <summary>
    /// Whether the counter an authenticator just presented proves the credential has been cloned.
    /// <para>
    /// <b>Both counters must be non-zero.</b> A large family of authenticators - most Apple and
    /// Android platform authenticators among them - deliberately report a constant zero, because a
    /// counter that increments is a cross-site correlation handle. For those the stored value stays
    /// zero forever and every assertion presents zero, so a rule of "not strictly greater than the
    /// stored value is a clone" would lock out every iPhone in the user base on the second login.
    /// The rule therefore fires only when the authenticator is counting (<paramref name="presented"/>
    /// &gt; 0) and we have a counted value to compare against - and note that
    /// <paramref name="presented"/> &gt; 0 combined with <paramref name="presented"/> ≤
    /// <paramref name="stored"/> already implies <paramref name="stored"/> &gt; 0.
    /// </para>
    /// <para>
    /// Equality counts as a clone, not as a replay of the same login: a counting authenticator
    /// increments before it signs, so the same value twice means two authenticators.
    /// </para>
    /// <para>
    /// This mirrors step 21 of the WebAuthn assertion verification, which the FIDO2 library also
    /// enforces. It is duplicated here on purpose - the check is the entire security advantage of
    /// a passkey, and it should not be possible to lose it by swapping a library.
    /// </para>
    /// </summary>
    public static bool IndicatesClone(long stored, long presented) => presented > 0 && presented <= stored;

    /// <summary>
    /// Records a successful assertion: advances the counter, refreshes the backup state and stamps
    /// the last-used time.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> when <paramref name="presentedSignCount"/> indicates a clone, in
    /// which case <b>nothing is mutated</b> - the caller must refuse the login. The counter is not
    /// advanced towards the clone's value either, so the genuine authenticator can still sign in.
    /// </returns>
    public bool RecordAssertion(long presentedSignCount, bool backupState, DateTimeOffset now)
    {
        if (IndicatesClone(SignCount, presentedSignCount))
        {
            return false;
        }

        // Only ever forward. A zero-counter authenticator presents 0 against a stored 0 and leaves
        // it alone; a counting one moves it up. Max() rather than a plain assignment so that a
        // legitimate zero from an authenticator that stopped counting cannot silently reset a
        // counter that had been advancing - which would hand a real clone a clean slate.
        SignCount = Math.Max(SignCount, presentedSignCount);
        BackupState = backupState;
        LastUsedAt = now;
        UpdatedAt = now;

        return true;
    }

    /// <summary>Relabels the credential. Trimmed, and an empty label falls back to
    /// <see cref="DefaultName"/> rather than being stored as an empty string that renders as a
    /// blank row in the client's list.</summary>
    public void Rename(string name, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(name);

        var trimmed = name.Trim();
        Name = trimmed.Length == 0 ? DefaultName : trimmed;
        UpdatedAt = now;
    }
}
