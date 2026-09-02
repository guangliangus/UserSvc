using UserSvc.Domain.Abstractions;

namespace UserSvc.Domain.Verification;

/// <summary>
/// One issued verification code, and - once it has been verified - the ticket minted from it.
/// <para>
/// The row is stored in PostgreSQL rather than Redis on purpose: it is the audit trail of every
/// code this service ever sent, and risk control counts it when Redis is unavailable. Nothing here
/// is ever deleted; the lifecycle is carried by <see cref="VerifiedAt"/> and
/// <see cref="ConsumedAt"/>.
/// </para>
/// <para>
/// <b>No plaintext is stored.</b> All three of <see cref="TargetHash"/>, <see cref="CodeHash"/> and
/// <see cref="VerificationTicketHash"/> are blind indexes - keyed HMAC-SHA256 under the identifier
/// pepper, not a bare digest - over values that otherwise exist only in transit. The key matters
/// most for the code: six digits under an un-keyed digest is a million-entry rainbow table, so a
/// dump of this table alone would hand over every live code. With the pepper held outside the
/// database, reading the table reveals neither who was sent a code nor what it was.
/// </para>
/// <para>
/// Deliberately flat (decision 04) apart from <see cref="Issue"/>. The invariants that matter here
/// - a code is verified at most once, a ticket is consumed at most once - cannot be enforced in
/// memory at all: two concurrent requests both read an unverified row and both would pass an
/// in-memory check. They are enforced by conditional UPDATEs whose WHERE clause carries the
/// precondition, so the database decides the winner. Putting those rules in this class would look
/// like protection and provide none.
/// </para>
/// </summary>
public sealed class VerificationCode
{
    /// <summary>
    /// The error code a code that is born expired is refused with. It is spelled the same as
    /// <c>ErrorCodes.VerificationCodeExpired</c> in the application layer - the domain cannot
    /// reference that class (decision 03), and a client that sees this errorCode must not be able
    /// to tell which layer produced it.
    /// </summary>
    public const string ExpiredErrorCode = "VERIFICATION_CODE_EXPIRED";

    public int Id { get; set; }

    /// <summary>Blind index over the trimmed, lowercased target. See <c>VerificationHashing</c> for
    /// why this normalization is not the identity-type-aware one.</summary>
    public string TargetHash { get; set; } = string.Empty;

    /// <summary>Blind index over the <c>X-Device-ID</c> header captured at send time, or the empty
    /// string when the caller sent no device id. Feeds the device dimension of the risk-control
    /// fallback count.</summary>
    public string DeviceIdHash { get; set; } = string.Empty;

    /// <summary>See <see cref="VerificationPurposes"/>.</summary>
    public string Purpose { get; set; } = string.Empty;

    /// <summary>Blind index over the six digits that were sent - see
    /// <c>VerificationHashing.HashSecret</c>, which hashes it exactly as typed, with no trimming
    /// and no case folding.</summary>
    public string CodeHash { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>When the code was exchanged for a ticket. Null until then, and the one-time-use
    /// guard of the verify path is <c>WHERE verified_at IS NULL</c>.</summary>
    public DateTimeOffset? VerifiedAt { get; set; }

    /// <summary>Blind index over the ticket handed to the client, or the empty string before one is
    /// minted. The plaintext ticket exists only in the verify response.</summary>
    public string VerificationTicketHash { get; set; } = string.Empty;

    /// <summary>The ticket's own deadline. It deliberately inherits nothing from
    /// <see cref="ExpiresAt"/>: the code's TTL bounds how long the user has to type it, the
    /// ticket's bounds how long the flow that follows has to finish.</summary>
    public DateTimeOffset? VerificationTicketExpiresAt { get; set; }

    /// <summary>When the row was retired - either by the flow consuming its ticket, or by a newer
    /// code for the same target and purpose superseding it. Permanent; a consumed row never comes
    /// back to life.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public string CreatedBy { get; set; } = string.Empty;

    public string UpdatedBy { get; set; } = string.Empty;

    /// <summary>
    /// Build the row about to be inserted, refusing one that is already dead on arrival.
    /// <para>
    /// The expiry check is the guard the Go original ran before touching the database, and it is
    /// kept for the same reason: a code row whose <c>expires_at</c> is already in the past can
    /// never be verified, so inserting it would produce a send that reports success and a code
    /// that has no chance of working. Failing loudly at the boundary turns a silent
    /// "the code never works" into a visible error.
    /// </para>
    /// <para>
    /// <paramref name="createdAt"/> defaults to <paramref name="now"/> when left unset, so a caller
    /// that only cares about the expiry cannot accidentally write the epoch into the audit trail
    /// and disappear from every window count.
    /// </para>
    /// </summary>
    /// <exception cref="DomainRuleException">The code expires at or before <paramref name="now"/>.</exception>
    public static VerificationCode Issue(
        string targetHash,
        string deviceIdHash,
        string purpose,
        string codeHash,
        DateTimeOffset expiresAt,
        DateTimeOffset createdAt,
        DateTimeOffset now,
        string actor)
    {
        if (expiresAt <= now)
        {
            throw new DomainRuleException(
                ExpiredErrorCode,
                "The verification code has already expired and would never be verifiable.");
        }

        return new VerificationCode
        {
            TargetHash = targetHash,
            DeviceIdHash = deviceIdHash,
            Purpose = purpose,
            CodeHash = codeHash,
            ExpiresAt = expiresAt,
            CreatedAt = createdAt == default ? now : createdAt,
            CreatedBy = actor,
            UpdatedBy = actor,
        };
    }
}

/// <summary>
/// Who a verification-code row is stamped as created or updated by. Sending a code is a public,
/// unauthenticated endpoint, so in practice every row carries <see cref="System"/>.
/// </summary>
public static class VerificationActors
{
    public const string System = "system";
}
