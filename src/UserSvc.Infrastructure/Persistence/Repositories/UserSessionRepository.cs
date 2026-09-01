using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Auth;
using UserSvc.Domain.Auth;

namespace UserSvc.Infrastructure.Persistence.Repositories;

public sealed class UserSessionRepository(UserSvcDbContext db) : IUserSessionRepository
{
    public Task<UserSession?> FindBySessionIdAsync(string sessionId, CancellationToken cancellationToken) =>
        db.UserSessions.FirstOrDefaultAsync(s => s.SessionId == sessionId, cancellationToken);

    public async Task<IReadOnlyList<UserSession>> ListActiveByUserAsync(
        int userId,
        CancellationToken cancellationToken) =>
        await db.UserSessions
            .Where(s => s.UserId == userId && s.Status == SessionStatuses.Active)
            .ToListAsync(cancellationToken);

    public void Add(UserSession session) => db.UserSessions.Add(session);
}
