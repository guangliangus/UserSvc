using UserSvc.Domain.Verification;

namespace UserSvc.Application.Ports.Verification;

/// <summary>
/// The verification-code table. There is a database on the other side, so it is a port.
/// <para>
/// <b>Every method takes raw values and hashes them itself.</b> That is not an accident of the
/// port's shape, it is the point: the target and the code are hashed in exactly one place, so a
/// caller cannot hash a target one way on the way in and another way on the way out and quietly
/// produce a code that can never be found again. The price is that the adapter needs the pepper -
/// a trade worth making, because the failure it prevents is invisible in testing (the send
/// succeeds, only the verify fails) and would strand real users.
/// </para>
/// <para>
/// Both write paths carry their preconditions in a WHERE clause rather than in a read-then-write.
/// Two concurrent verifies of the same code both read an unverified row; only the conditional
/// UPDATE decides which one wins. Anything softer is a race with a security consequence.
/// </para>
/// <para>
/// Consuming a ticket is <b>not</b> here: it is <see cref="IVerificationTicketConsumer"/>, so the
/// auth slices that only ever spend a ticket depend on one method instead of on all of this.
/// </para>
/// </summary>
public interface IVerificationCodeRepository
{
    /// <summary>
    /// Retire every still-live code for the same target and purpose, then insert the new one, and
    /// return its id.
    /// <para>
    /// The retirement is what makes "at most one live code per target and purpose" true, and it is
    /// why the caller must run this inside a transaction: a crash between the two statements would
    /// otherwise leave the target with no usable code at all. The returned id becomes the
    /// notification's idempotency key, which is the only reason this method returns anything.
    /// </para>
    /// </summary>
    Task<int> CreateAsync(NewVerificationCode code, CancellationToken cancellationToken);

    /// <summary>
    /// Exchange a correct, live code for a verification ticket, stamping both on the code row.
    /// <para>
    /// A miss is classified rather than reported flatly, because "you typed it wrong" and "it
    /// expired" call for different things from the user - retype, or ask for a new one - and only
    /// the row can tell them apart.
    /// </para>
    /// </summary>
    /// <exception cref="Errors.BadRequestException">
    /// <c>VERIFICATION_CODE_INCORRECT</c> when no row matches or the row was already used,
    /// <c>VERIFICATION_CODE_EXPIRED</c> when a row matches but its deadline has passed.
    /// </exception>
    Task VerifyCodeAndIssueTicketAsync(
        string target,
        string purpose,
        string code,
        string ticket,
        DateTimeOffset ticketExpiresAt,
        CancellationToken cancellationToken);

    /// <summary>
    /// How many codes were created for a target or a device since <paramref name="since"/>.
    /// <para>
    /// This is the fallback risk control was meant to count on when Redis is unavailable. <b>It has
    /// no production caller today</b> - risk control counts in Redis and fails open by contract - so
    /// this method and its <see cref="VerificationCountDimension"/> are a port surface kept for the
    /// day the fallback is actually wired, not a live path. <paramref name="rawValue"/> is normalized
    /// and hashed the same way <see cref="CreateAsync"/> stored it, so the count matches the rows
    /// that exist; a blank value therefore matches nothing and answers zero.
    /// </para>
    /// <para>
    /// <b>Only the <see cref="VerificationCountDimension.Target"/> dimension is indexed.</b> Its
    /// index <c>ix_verification_codes_target_hash_created_at</c> is kept for the failed-verify miss
    /// classification and covers the target count as well. The device index was dropped as unused
    /// write amplification (see db/0003_verification.sql), so a
    /// <see cref="VerificationCountDimension.Device"/> count sequentially scans the table until that
    /// index is recreated - which anyone wiring the device fallback must do first.
    /// </para>
    /// </summary>
    Task<long> CountInWindowAsync(
        VerificationCountDimension dimension,
        string rawValue,
        DateTimeOffset since,
        CancellationToken cancellationToken);
}

/// <summary>The row <see cref="IVerificationCodeRepository.CreateAsync"/> is about to write.</summary>
/// <param name="Target">The raw phone or email. Normalized and hashed by the adapter; never stored as text.</param>
/// <param name="DeviceId">The raw <c>X-Device-ID</c>, or the empty string. Hashed the same way, so
/// the device-dimension count matches the rows this insert creates.</param>
/// <param name="Purpose">See <see cref="VerificationPurposes"/>.</param>
/// <param name="Code">The plaintext code that was generated. Only its blind index reaches the database.</param>
/// <param name="ExpiresAt">When the code stops being verifiable. Must be in the future.</param>
/// <param name="CreatedAt">When the code was issued; <c>default</c> is filled in with the current time.</param>
public sealed record NewVerificationCode(
    string Target,
    string DeviceId,
    string Purpose,
    string Code,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt);
