using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Auth;
using UserSvc.Domain.Auth;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// EF Core implementation of <see cref="IUserSessionRepository"/>.
/// <para>
/// The subject predicate is spelled out once, here, as realm <b>and</b> id. Both halves are
/// equality predicates, which is what makes the partial unique index on
/// (realm, user_id, device_id) WHERE status = 'ACTIVE' serve this query from its leading columns.
/// </para>
/// </summary>
public sealed class UserSessionRepository(UserSvcDbContext db) : IUserSessionRepository
{
    /// <inheritdoc />
    public Task<UserSession?> FindBySessionIdAsync(string sessionId, CancellationToken cancellationToken) =>
        db.UserSessions.FirstOrDefaultAsync(s => s.SessionId == sessionId, cancellationToken);

    /// <inheritdoc />
    public async Task<IReadOnlyList<UserSession>> ListActiveBySubjectAsync(
        SessionSubject subject,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subject);

        // Captured into locals because EF translates a parameter, not a property walk on a domain
        // record - and because forgetting one of the two would compile perfectly.
        var realm = subject.Realm;
        var userId = subject.UserId;

        return await db.UserSessions
            .Where(s => s.Realm == realm && s.UserId == userId && s.Status == SessionStatuses.Active)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public void Add(UserSession session) => db.UserSessions.Add(session);
}
