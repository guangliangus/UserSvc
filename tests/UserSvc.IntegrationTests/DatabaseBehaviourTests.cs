using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Users;
using UserSvc.IntegrationTests.Infrastructure;
using UserSvc.Infrastructure.Persistence;

namespace UserSvc.IntegrationTests;

/// <summary>
/// Behaviour that only a real PostgreSQL server has: a partial unique index, a global query filter
/// running against actual rows, and the <c>xmin</c> concurrency token. An in-memory or mocked
/// store answers all four of these tests the wrong way and never fails.
/// </summary>
public sealed class DatabaseBehaviourTests(ServiceFixture fixture) : IntegrationTest(fixture)
{
    private static readonly Uri ProfilePath = new("/api/v1/user/profile", UriKind.Relative);

    private const string PhoneHash = "b0a1f2c3d4e5f60718293a4b5c6d7e8f";

    [RequiresDockerFact]
    public async Task ASecondActiveIdentityWithTheSameIdentifierIsRefusedAsAConflictRatherThanARawUniqueViolation()
    {
        var userId = await Fixture.SeedUserAsync();
        await AddIdentityAsync(userId, UserStatuses.Active);

        await using var scope = Fixture.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<UserSvcDbContext>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();

        db.UserIdentities.Add(NewIdentity(userId, UserStatuses.Active));

        var conflict = await Should.ThrowAsync<ConflictException>(
            async () => await unitOfWork.SaveChangesAsync(CancellationToken.None),
            "ix_user_identities_identity_type_identifier_hash covers ACTIVE rows, so binding the "
            + "same identifier twice must be refused by the database.");

        conflict.StatusCode.ShouldBe(
            (int)HttpStatusCode.Conflict,
            "A uniqueness violation is a state conflict the caller can react to, not a 500.");
        conflict.ErrorCode.ShouldBe(
            ErrorCodes.Conflict,
            "UnitOfWork must translate PostgreSQL 23505 into the client-facing error vocabulary; "
            + "leaking the SQLSTATE would make the contract the database's, not ours.");

        var postgres = conflict.InnerException
            .ShouldBeOfType<DbUpdateException>()
            .InnerException
            .ShouldBeOfType<PostgresException>();

        postgres.SqlState.ShouldBe("23505", "The cause must survive into the log even though it never reaches the body.");
        postgres.ConstraintName.ShouldBe("ix_user_identities_identity_type_identifier_hash");
    }

    [RequiresDockerFact]
    public async Task TheSameIdentifierCanBeBoundAgainOnceTheFirstBindingIsNoLongerActive()
    {
        var userId = await Fixture.SeedUserAsync();
        await AddIdentityAsync(userId, UserStatuses.Active);

        await using (var unbind = Fixture.CreateScope())
        {
            var db = unbind.ServiceProvider.GetRequiredService<UserSvcDbContext>();
            var unitOfWork = unbind.ServiceProvider.GetRequiredService<IUnitOfWork>();

            var identity = await db.UserIdentities.SingleAsync(i => i.UserId == userId);
            identity.Status = UserStatuses.Deleted;
            await unitOfWork.SaveChangesAsync(CancellationToken.None);
        }

        await using (var rebind = Fixture.CreateScope())
        {
            var db = rebind.ServiceProvider.GetRequiredService<UserSvcDbContext>();
            var unitOfWork = rebind.ServiceProvider.GetRequiredService<IUnitOfWork>();

            db.UserIdentities.Add(NewIdentity(userId, UserStatuses.Active));

            await Should.NotThrowAsync(
                async () => await unitOfWork.SaveChangesAsync(CancellationToken.None),
                "The unique index is partial (WHERE status = 'ACTIVE'), so an unbound identifier "
                + "must be attachable again - that is the whole reason it is not a plain UNIQUE.");
        }

        var statuses = await Fixture.QueryStringsAsync(
            "SELECT status FROM identity.user_identities WHERE user_id = @p0 ORDER BY id", userId);

        statuses.ShouldBe(
            [UserStatuses.Deleted, UserStatuses.Active],
            "The first binding is retained as history; nothing is physically deleted.");
    }

    [RequiresDockerFact]
    public async Task ASoftDeletedUserDisappearsFromOrdinaryQueriesWhileItsRowStaysInTheTable()
    {
        var userId = await Fixture.SeedUserAsync();
        using var client = Fixture.CreateDevClient(userId);

        using (var beforeDeletion = await client.GetAsync(ProfilePath))
        {
            beforeDeletion.StatusCode.ShouldBe(HttpStatusCode.OK, "The user is ACTIVE and readable.");
        }

        await Fixture.ExecuteAsync(
            "UPDATE identity.users SET status = @p0 WHERE id = @p1", UserStatuses.Deleted, userId);

        using (var afterDeletion = await client.GetAsync(ProfilePath))
        {
            afterDeletion.StatusCode.ShouldBe(HttpStatusCode.NotFound);

            var problem = await ProblemDetailsBody.ReadAsync(afterDeletion);
            problem.ErrorCode.ShouldBe(
                ErrorCodes.UserNotFound,
                "A DELETED user must look absent to the API, not merely inactive.");
        }

        (await Fixture.CountAsync("SELECT count(*) FROM identity.users WHERE id = @p0", userId))
            .ShouldBe(1, "Soft delete means the row survives; only the query filter hides it.");

        await using var scope = Fixture.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<UserSvcDbContext>();

        (await db.Users.CountAsync(u => u.Id == userId))
            .ShouldBe(0, "The global query filter must exclude DELETED rows from every ordinary query.");
        (await db.Users.IgnoreQueryFilters().CountAsync(u => u.Id == userId))
            .ShouldBe(1, "IgnoreQueryFilters is the only way to see it, which proves the filter is what hid it.");
    }

    /// <summary>
    /// A deterministic optimistic-concurrency race, staged with a row lock rather than a sleep.
    /// <para>
    /// This is a regression test with a real defect behind it: losing the <c>xmin</c> race used to
    /// answer an opaque 500. The status code is the whole point, so the assertion is made on the
    /// HTTP response and not on the exception type.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task AWriteThatLosesTheXminRaceComesBackAsA409ConcurrencyConflict()
    {
        var userId = await Fixture.SeedUserAsync();
        using var client = Fixture.CreateDevClient(userId);

        await using var blocker = Fixture.CreateConnection();
        await blocker.OpenAsync();
        await using var transaction = await blocker.BeginTransactionAsync();

        await using (var competingWrite = new NpgsqlCommand(
                         "UPDATE identity.users SET nickname = 'winner' WHERE id = @p0", blocker, transaction))
        {
            competingWrite.Parameters.AddWithValue("p0", userId);
            (await competingWrite.ExecuteNonQueryAsync()).ShouldBe(1);
        }

        // MVCC lets the request read the row, so it loads the pre-race xmin and then blocks on the
        // UPDATE behind the lock held above.
        using var payload = new StringContent(
            """{"nickname":"loser"}""", Encoding.UTF8, "application/json");
        var patch = client.PatchAsync(ProfilePath, payload);

        await WaitUntilARequestIsBlockedOnTheRowAsync();

        // Committing bumps xmin. Under READ COMMITTED PostgreSQL re-evaluates the blocked UPDATE
        // against the new row version, the xmin predicate no longer matches, zero rows are
        // affected, and EF raises DbUpdateConcurrencyException.
        await transaction.CommitAsync();

        using var response = await patch;

        response.StatusCode.ShouldBe(
            HttpStatusCode.Conflict,
            "Losing the xmin race means 'someone else got there first; re-read and retry', which is "
            + "409. It used to surface as an opaque 500.");

        var problem = await ProblemDetailsBody.ReadAsync(response);
        problem.ContentType.ShouldBe("application/problem+json");
        problem.ErrorCode.ShouldBe(
            ErrorCodes.ConcurrencyConflict,
            "CONFLICT and CONCURRENCY_CONFLICT mean different things to a client: one is a duplicate, "
            + "the other is a stale read that a retry fixes.");
        problem.TraceId.ShouldNotBeNullOrEmpty();

        (await Fixture.QueryStringsAsync("SELECT nickname FROM identity.users WHERE id = @p0", userId))
            .ShouldBe(["winner"], "The losing write must not have been applied.");
    }

    private async Task WaitUntilARequestIsBlockedOnTheRowAsync()
    {
        var deadline = DateTime.UtcNow.AddSeconds(20);

        while (DateTime.UtcNow < deadline)
        {
            var blocked = await Fixture.CountAsync(
                """
                SELECT count(*) FROM pg_stat_activity
                WHERE datname = current_database() AND wait_event_type = 'Lock'
                """);

            if (blocked > 0)
            {
                return;
            }

            await Task.Delay(50);
        }

        throw new InvalidOperationException(
            "No backend ever blocked on the locked user row, so the concurrency race was never staged. "
            + "The request under test probably failed before it reached its UPDATE.");
    }

    private async Task AddIdentityAsync(int userId, string status)
    {
        await using var scope = Fixture.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<UserSvcDbContext>();
        db.UserIdentities.Add(NewIdentity(userId, status));
        await db.SaveChangesAsync();
    }

    private static UserIdentity NewIdentity(int userId, string status)
    {
        var now = DateTimeOffset.UtcNow;

        return new UserIdentity
        {
            UserId = userId,
            IdentityType = IdentityTypes.Phone,
            IdentifierHash = PhoneHash,
            IdentifierCiphertext = "ciphertext",
            IdentifierKeyVersion = "dev",
            Status = status,
            CreatedAt = now,
            UpdatedAt = now,
        };
    }
}
