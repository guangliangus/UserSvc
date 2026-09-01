using UserSvc.Domain.Auth;

namespace UserSvc.Application.Ports.Auth;

/// <summary>Persistence outlet for login sessions.</summary>
public interface IUserSessionRepository
{
    Task<UserSession?> FindBySessionIdAsync(string sessionId, CancellationToken cancellationToken);

    Task<IReadOnlyList<UserSession>> ListActiveByUserAsync(int userId, CancellationToken cancellationToken);

    void Add(UserSession session);
}
