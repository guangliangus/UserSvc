using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Users;
using UserSvc.Domain.Users;

namespace UserSvc.Infrastructure.Persistence.Repositories;

public sealed class UserIdentityRepository(UserSvcDbContext db) : IUserIdentityRepository
{
    /// <summary>
    /// Reads with change tracking disabled: the caller only asks whether the identifier is taken
    /// and never writes to what comes back, so tracking it would cost a snapshot and, worse, make
    /// a later accidental mutation savable.
    /// </summary>
    public Task<UserIdentity?> FindActiveAsync(
        string identityType,
        string identifierHash,
        CancellationToken cancellationToken) =>
        db.UserIdentities
            .AsNoTracking()
            .FirstOrDefaultAsync(
                i => i.IdentityType == identityType
                     && i.IdentifierHash == identifierHash
                     && i.Status == UserStatuses.Active,
                cancellationToken);
}
