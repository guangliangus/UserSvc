using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Verification;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Verification;
using UserSvc.Application.Security;
using UserSvc.Domain.Verification;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// The verification-code table, and the only place its three secrets are hashed.
/// <para>
/// <b>Every state change is a conditional UPDATE, never a read-then-write.</b> Two requests
/// verifying the same code both read an unverified row; if the guard lived in memory both would
/// pass it and both would be handed a ticket. Putting the precondition in the WHERE clause makes
/// PostgreSQL the arbiter: the second UPDATE matches nothing, reports zero rows, and is refused.
/// The pattern is what makes "a code is used once" and "a ticket is consumed once" true rather
/// than merely intended.
/// </para>
/// </summary>
public sealed class VerificationCodeRepository(
    UserSvcDbContext db,
    IdentifierProtector protector,
    IClock clock) : IVerificationCodeRepository, IVerificationTicketConsumer
{
    private IQueryable<VerificationCode> Rows => db.Set<VerificationCode>();

    public async Task<int> CreateAsync(NewVerificationCode code, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);

        var now = clock.UtcNow;
        var targetHash = VerificationHashing.HashTarget(protector, code.Target);
        var purpose = code.Purpose;

        // Built before any database access, so a code that could never be verified is refused
        // without having retired the live one that still worked.
        var row = VerificationCode.Issue(
            targetHash,
            VerificationHashing.HashDeviceId(protector, code.DeviceId),
            purpose,
            VerificationHashing.HashSecret(protector, code.Code),
            code.ExpiresAt,
            code.CreatedAt,
            now,
            VerificationActors.System);

        // Retiring the previous live codes is what keeps "at most one live code per target and
        // purpose" true. Without it, an attacker who triggers a dozen sends gets a dozen valid
        // codes at once and twelve times the chance of a lucky guess.
        await db.Set<VerificationCode>()
            .Where(c => c.TargetHash == targetHash && c.Purpose == purpose && c.ConsumedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(c => c.ConsumedAt, now)
                    .SetProperty(c => c.UpdatedBy, VerificationActors.System),
                cancellationToken);

        var entry = db.Set<VerificationCode>().Add(row);

        try
        {
            // Saved through the context rather than IUnitOfWork because this method has to hand
            // back the generated id, and because the caller has already opened the transaction
            // that makes the retire-then-insert pair atomic.
            await db.SaveChangesAsync(cancellationToken);
        }
        catch
        {
            // The caller's transaction body is replayed on a transient PostgreSQL failure, and an
            // entity left in Added state is inserted a second time by the retry's SaveChanges -
            // alongside the row that attempt adds. Two live codes for one target and purpose is
            // precisely what the retirement above exists to prevent, so the failed attempt has to
            // take its entity with it.
            entry.State = EntityState.Detached;
            throw;
        }

        return row.Id;
    }

    public async Task VerifyCodeAndIssueTicketAsync(
        string target,
        string purpose,
        string code,
        string ticket,
        DateTimeOffset ticketExpiresAt,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;

        if (ticketExpiresAt <= now)
        {
            throw new BadRequestException(
                ErrorCodes.VerificationCodeExpired,
                "The verification ticket would expire before it could be used.");
        }

        var targetHash = VerificationHashing.HashTarget(protector, target);
        var codeHash = VerificationHashing.HashSecret(protector, code);

        // Zero is a safe "no candidate" sentinel: the key is a SERIAL and starts at one.
        var candidateId = await Rows
            .Where(c => c.TargetHash == targetHash
                        && c.Purpose == purpose
                        && c.CodeHash == codeHash
                        && c.VerifiedAt == null
                        && c.ConsumedAt == null
                        && c.ExpiresAt > now)
            .OrderByDescending(c => c.CreatedAt)
            .Select(c => c.Id)
            .FirstOrDefaultAsync(cancellationToken);

        if (candidateId == 0)
        {
            throw await ClassifyMissAsync(targetHash, purpose, codeHash, now, cancellationToken);
        }

        var ticketHash = VerificationHashing.HashSecret(protector, ticket);

        // The guard repeated in the WHERE clause is not redundant with the query above: another
        // request may have verified this same row in between. Whoever loses that race is told the
        // code is used, not handed a second ticket for it.
        var updated = await Rows
            .Where(c => c.Id == candidateId && c.VerifiedAt == null && c.ConsumedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(c => c.VerifiedAt, now)
                    .SetProperty(c => c.VerificationTicketHash, ticketHash)
                    .SetProperty(c => c.VerificationTicketExpiresAt, ticketExpiresAt)
                    .SetProperty(c => c.UpdatedBy, VerificationActors.System),
                cancellationToken);

        if (updated == 0)
        {
            throw new BadRequestException(
                ErrorCodes.VerificationCodeIncorrect,
                "That verification code has already been used.");
        }
    }

    public async Task<bool> TryConsumeAsync(
        string target,
        string purpose,
        string ticket,
        CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        var targetHash = VerificationHashing.HashTarget(protector, target);
        var ticketHash = VerificationHashing.HashSecret(protector, ticket);

        // Five conditions in one statement, and every one of them is load-bearing: the ticket must
        // exist, have been verified, not have been spent, not have expired, and belong to this
        // target and purpose. Dropping the purpose alone would let a ticket minted to reset a
        // consumer password authorise a back-office one.
        var consumed = await Rows
            .Where(c => c.TargetHash == targetHash
                        && c.Purpose == purpose
                        && c.VerificationTicketHash == ticketHash
                        && c.VerifiedAt != null
                        && c.ConsumedAt == null
                        && c.VerificationTicketExpiresAt > now)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(c => c.ConsumedAt, now)
                    .SetProperty(c => c.UpdatedBy, VerificationActors.System),
                cancellationToken);

        // Exactly one row, or none. The UPDATE is the gate, so its row count is the answer - and
        // the caller learns only that, never whether the ticket was unknown, spent or merely late.
        return consumed > 0;
    }

    public Task<long> CountInWindowAsync(
        VerificationCountDimension dimension,
        string rawValue,
        DateTimeOffset since,
        CancellationToken cancellationToken)
    {
        var hashed = VerificationHashing.HashTarget(protector, rawValue);

        // A blank value hashes to something no row carries - absent device ids are stored as the
        // empty string - so it counts zero rather than matching every anonymous send.
        var scoped = dimension switch
        {
            VerificationCountDimension.Target => Rows.Where(c => c.TargetHash == hashed),
            VerificationCountDimension.Device => Rows.Where(c => c.DeviceIdHash == hashed),
            _ => throw new AppException(
                ErrorCodes.InternalError,
                "The request could not be completed.",
                500),
        };

        return scoped.Where(c => c.CreatedAt >= since).LongCountAsync(cancellationToken);
    }

    /// <summary>
    /// Tell "you typed it wrong" apart from "it expired", because the two ask different things of
    /// the user - retype, or request a new code - and only the row knows which happened.
    /// <para>
    /// A row that matches and has not expired means the code was already verified or consumed. That
    /// answers <c>INCORRECT</c> rather than something more precise on purpose: an attacker holding
    /// a guessed code must not learn that the guess was right and merely late.
    /// </para>
    /// </summary>
    private async Task<AppException> ClassifyMissAsync(
        string targetHash,
        string purpose,
        string codeHash,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var deadline = await Rows
            .Where(c => c.TargetHash == targetHash && c.Purpose == purpose && c.CodeHash == codeHash)
            .OrderByDescending(c => c.CreatedAt)
            .Select(c => (DateTimeOffset?)c.ExpiresAt)
            .FirstOrDefaultAsync(cancellationToken);

        return deadline is { } expiresAt && expiresAt <= now
            ? new BadRequestException(
                ErrorCodes.VerificationCodeExpired,
                "That verification code has expired. Request a new one.")
            : new BadRequestException(
                ErrorCodes.VerificationCodeIncorrect,
                "That verification code is not correct.");
    }
}
