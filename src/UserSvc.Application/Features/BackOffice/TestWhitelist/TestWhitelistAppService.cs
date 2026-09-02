using System.Globalization;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Consumers;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.TestWhitelist;
using UserSvc.Application.Ports.Users;
using UserSvc.Domain.TestWhitelist;

namespace UserSvc.Application.Features.BackOffice.TestWhitelist;

/// <summary>
/// The consumer test-user whitelist: the set of C-end accounts allowed to additionally see, and
/// order, the test company's tour products.
/// <para>
/// The verdict leaves this service as the <c>is_test</c> flag on token validation, which the
/// product and order services already call on every authenticated request. This service
/// deliberately does not know the test company's code - it answers only "is this account a test
/// user", and what that entitles them to see belongs to the services that sell things.
/// </para>
/// <para>
/// <b>Every method except <see cref="IsTestUserAsync"/> is an administrative operation restricted
/// to the platform super administrator</b>, and the guard lives here rather than on the route
/// because it reads the flag from the account row: a revoked flag then takes effect on the next
/// request instead of at the holder's next token refresh. There is no permission code for these
/// routes at all, which is the same decision seen from the other side - a permission point granted
/// to exactly one boolean flag is an indirection with no payoff, and seeding one would lock every
/// signed-in administrator out until they re-authenticated.
/// </para>
/// <para>
/// <b>Storage is a table, not a cache.</b> The Go original kept the list in a single Redis set, on
/// the argument that losing the key merely empties the whitelist and that failure direction is
/// safe. That reasoning holds for the read and not for the write: an operator who adds a tester and
/// finds the list empty next week has no way to tell whether somebody removed them or the key
/// expired. A table also comes with the two columns that answer every question actually asked of
/// this list afterwards - who added an entry, and when - and lets a removal be soft, so the record
/// that an account was a tester between two dates survives the removal.
/// </para>
/// </summary>
public sealed class TestWhitelistAppService(
    AdminScopeService adminScopes,
    ITestWhitelistRepository whitelist,
    IUserRepository users,
    ConsumerSummaryService summaries,
    IamAuditWriter audit,
    IUnitOfWork unitOfWork,
    IClock clock,
    ILogger<TestWhitelistAppService> logger)
{
    /// <summary>
    /// Whether a <b>consumer</b> account is whitelisted.
    /// <para>
    /// <b>It never throws, on purpose.</b> This runs inside token validation - the hottest
    /// authenticated path in the platform - and any error a caller could receive here is one the
    /// caller could propagate, turning a whitelist hiccup into a platform-wide authentication
    /// failure. A store it cannot reach yields false, which hides test products: the fail-closed
    /// direction.
    /// </para>
    /// <para>
    /// <b>Caller contract: the id MUST come from <c>identity.users</c>.</b> This method is
    /// realm-blind - it compares whatever id it is handed against the table - so a back-office id
    /// that happens to equal a whitelisted consumer id would come back true. The single caller is
    /// expected to skip it for an internal subject, and a second caller has to carry the same
    /// guard.
    /// </para>
    /// </summary>
    public async Task<bool> IsTestUserAsync(int userId, CancellationToken cancellationToken)
    {
        if (userId <= 0)
        {
            return false;
        }

        try
        {
            return await whitelist.IsWhitelistedAsync(userId, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // The caller gave up on the request. That is not a degraded read and must keep
            // propagating as cancellation rather than being reported as "not a test user".
            throw;
        }
        catch (Exception ex)
        {
            // Warning, not error: this is a degraded read, not a fault in the request being served.
            logger.LogWarning(
                ex,
                "The test whitelist could not be read for consumer account {UserId}; treating it "
                + "as a non-test account.",
                userId);

            return false;
        }
    }

    /// <summary>
    /// One page of the whitelist, hydrated into summaries an operator can recognise.
    /// <para>
    /// Unlike <see cref="IsTestUserAsync"/>, a failure here <b>propagates</b>. An administrator must
    /// not be shown an empty list when the store is unreachable: it reads as "nobody is
    /// whitelisted" and invites them to re-add everyone, or to believe a removal succeeded.
    /// </para>
    /// </summary>
    public async Task<TestWhitelistListResponse> ListAsync(
        IBackOfficeCaller caller,
        int page,
        int pageSize,
        CancellationToken cancellationToken)
    {
        await adminScopes.AssertPlatformSuperAdminAsync(caller, cancellationToken);

        var (normalizedPage, normalizedPageSize) = TestWhitelistPaging.Normalize(page, pageSize);

        var ids = await whitelist.ListActiveUserIdsAsync(cancellationToken);

        // Hydrate only the current page - that is the whole point of paging here, since hydrating
        // is what decrypts identifiers.
        var pageIds = TestWhitelistPaging.Slice(ids, normalizedPage, normalizedPageSize);

        return new TestWhitelistListResponse
        {
            Items = await summaries.SummarizeAsync(pageIds, cancellationToken),
            Total = ids.Count,
            Page = normalizedPage,
            PageSize = normalizedPageSize,
            TotalPages = TestWhitelistPaging.TotalPages(ids.Count, normalizedPageSize),
        };
    }

    /// <summary>
    /// Put one consumer account on the whitelist. Idempotent: an account already on it succeeds and
    /// changes nothing.
    /// <para>
    /// Takes effect on that account's next request - the verdict is computed per token validation,
    /// not baked into an issued token - so nobody has to sign in again.
    /// </para>
    /// </summary>
    public async Task AddAsync(IBackOfficeCaller caller, int userId, CancellationToken cancellationToken)
    {
        await adminScopes.AssertPlatformSuperAdminAsync(caller, cancellationToken);

        if (userId <= 0)
        {
            throw new BadRequestException(ErrorCodes.BadRequest, "A consumer account id is required.");
        }

        // The id must belong to an account that can still authenticate: whitelist membership is
        // inert for one that cannot, and silently accepting such an id makes the list harder to
        // reason about. Deliberately NOT symmetric - an account disabled AFTER being whitelisted
        // keeps its entry, because it can no longer obtain a token and so can never present
        // is_test=true, and the operator can see the entry in the listing and remove it.
        //
        // This read is also what keeps the table consumer-only: it resolves the id against
        // identity.users, so a back-office account id cannot get in.
        var user = await users.FindByIdAsync(userId, cancellationToken)
                   ?? throw new NotFoundException(
                       // NOT_FOUND rather than the more specific USER_NOT_FOUND this service also
                       // publishes: the route's documented contract is the general code, and an
                       // error code is a client contract that is not ours to sharpen unilaterally.
                       ErrorCodes.NotFound, "No consumer account has this id.");

        if (!user.IsActive())
        {
            // The same error code as a missing account - the contract exposes one outcome for "this
            // id is not usable" - but a distinct message. This endpoint is super-administrator only,
            // so telling the operator why costs nothing and saves them hunting for a typo that is
            // not there.
            throw new NotFoundException(
                ErrorCodes.NotFound, "That consumer account is not active.");
        }

        var existing = await whitelist.FindAsync(userId, cancellationToken);
        if (existing is { Status: TestWhitelistStatuses.Active })
        {
            // Nothing changed, so there is nothing to audit. An idempotent call that wrote an audit
            // row would fill the trail with events that never happened.
            return;
        }

        var now = clock.UtcNow;
        var actor = Actor(caller);
        var before = existing is null
            ? null
            : new TestWhitelistAuditSnapshot(userId, existing.Status);

        if (existing is null)
        {
            whitelist.Add(new TestWhitelistEntry
            {
                UserId = userId,
                Status = TestWhitelistStatuses.Active,
                CreatedAt = now,
                UpdatedAt = now,
                CreatedBy = actor,
                UpdatedBy = actor,
            });
        }
        else
        {
            // Revived rather than inserted a second time, which is what the partial unique index
            // over the ACTIVE rows requires - and what keeps the original CreatedAt as the answer
            // to "since when has this account been a tester".
            existing.Status = TestWhitelistStatuses.Active;
            existing.UpdatedAt = now;
            existing.UpdatedBy = actor;
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);

        // Post-commit and best effort, like every other IAM audit write: the change stands, and
        // failing the request now would report a false negative to the operator.
        await audit.WriteAsync(
            caller,
            TestWhitelistAuditVocabulary.AddAction,
            TestWhitelistAuditVocabulary.TargetType,
            userId.ToString(CultureInfo.InvariantCulture),
            before,
            new TestWhitelistAuditSnapshot(userId, TestWhitelistStatuses.Active),
            cancellationToken);

        logger.LogInformation(
            "Consumer account {UserId} was added to the test whitelist by account {ActorUserId}.",
            userId,
            caller.UserId);
    }

    /// <summary>
    /// Take one consumer account off the whitelist. Idempotent - removing an id that is not on it
    /// succeeds.
    /// <para>
    /// <b>No existence check against <c>identity.users</c>.</b> An id whose account is gone is
    /// exactly the entry an operator most needs to be able to delete, and demanding that the
    /// account still exist would make an orphaned entry permanent.
    /// </para>
    /// </summary>
    public async Task RemoveAsync(IBackOfficeCaller caller, int userId, CancellationToken cancellationToken)
    {
        await adminScopes.AssertPlatformSuperAdminAsync(caller, cancellationToken);

        if (userId <= 0)
        {
            throw new BadRequestException(ErrorCodes.BadRequest, "A consumer account id is required.");
        }

        var existing = await whitelist.FindAsync(userId, cancellationToken);
        if (existing is null || existing.Status != TestWhitelistStatuses.Active)
        {
            // Already off the list. Nothing changed, so nothing is audited.
            return;
        }

        existing.Status = TestWhitelistStatuses.Removed;
        existing.UpdatedAt = clock.UtcNow;
        existing.UpdatedBy = Actor(caller);

        await unitOfWork.SaveChangesAsync(cancellationToken);

        await audit.WriteAsync(
            caller,
            TestWhitelistAuditVocabulary.RemoveAction,
            TestWhitelistAuditVocabulary.TargetType,
            userId.ToString(CultureInfo.InvariantCulture),
            new TestWhitelistAuditSnapshot(userId, TestWhitelistStatuses.Active),
            new TestWhitelistAuditSnapshot(userId, TestWhitelistStatuses.Removed),
            cancellationToken);

        logger.LogInformation(
            "Consumer account {UserId} was removed from the test whitelist by account {ActorUserId}.",
            userId,
            caller.UserId);
    }

    /// <summary>
    /// What goes into <c>created_by</c> / <c>updated_by</c>: the caller's display name, or
    /// <c>system</c> when the request carries none. The audit row records who it really was; these
    /// columns are for somebody reading the table directly.
    /// </summary>
    private static string Actor(IBackOfficeCaller caller) =>
        string.IsNullOrWhiteSpace(caller.Nickname) ? "system" : caller.Nickname;
}
