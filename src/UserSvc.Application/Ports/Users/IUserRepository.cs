using UserSvc.Domain.Users;

namespace UserSvc.Application.Ports.Users;

/// <summary>Persistence outlet for user profiles. There is a database on the other side, so it is a port.</summary>
public interface IUserRepository
{
    Task<User?> FindByIdAsync(int userId, CancellationToken cancellationToken);

    /// <summary>Exact lookup by blind index — the plaintext is never stored, so matching happens
    /// on the hash (decision 13).</summary>
    Task<User?> FindByIdentifierHashAsync(string identifierHash, CancellationToken cancellationToken);

    void Add(User user);
}
