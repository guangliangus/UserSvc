using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Users;
using UserSvc.Domain.Users;

namespace UserSvc.Infrastructure.Persistence.Repositories;

public sealed class UserRepository(UserSvcDbContext db) : IUserRepository
{
    public Task<User?> FindByIdAsync(int userId, CancellationToken cancellationToken) =>
        db.Users.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);

    public Task<User?> FindByIdentifierHashAsync(string identifierHash, CancellationToken cancellationToken) =>
        db.Users
            .Where(u => u.Identities.Any(i =>
                i.IdentifierHash == identifierHash && i.Status == UserStatuses.Active))
            .FirstOrDefaultAsync(cancellationToken);

    public void Add(User user) => db.Users.Add(user);
}
