using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.TestWhitelist;
using UserSvc.Domain.Users;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// The back office's read window onto consumer accounts, over the shared persistence context.
/// <para>
/// <b>This is the one place a back-office feature reads the consumer schema</b>, and the shape is
/// what keeps that crossing honest: two batch projections, no entity handed out, no write path, and
/// nothing that takes a search term. Both queries are untracked - the caller renders them and never
/// writes back - and both answer with the stored ciphertext rather than a plaintext, because
/// deciding how much of somebody's address an operator may see is a policy question and this is a
/// persistence adapter.
/// </para>
/// </summary>
public sealed class TestWhitelistConsumerDirectory(UserSvcDbContext db) : IConsumerAccountDirectory
{
    public async Task<IReadOnlyList<ConsumerAccountRow>> ListAccountsAsync(
        IReadOnlyList<int> userIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(userIds);

        if (userIds.Count == 0)
        {
            return [];
        }

        var wanted = userIds.ToArray();

        return await db.Users
            .AsNoTracking()
            .Where(user => wanted.Contains(user.Id))
            .Select(user => new ConsumerAccountRow(
                user.Id, user.FirstName, user.LastName, user.Nickname))
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// The ACTIVE phone and email identities of the named accounts, id ascending.
    /// <para>
    /// Third-party rows - a social login, a passkey - are excluded in the WHERE clause rather than
    /// filtered afterwards: they are not contact details, and a provider subject is not something
    /// an operator confirming a tester should be shown or this process should decrypt.
    /// </para>
    /// <para>
    /// The order is part of the port's contract, and it is here rather than in the caller so that
    /// "the first email identity" is the same row on every page load.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<ConsumerContactRow>> ListActiveContactsAsync(
        IReadOnlyList<int> userIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(userIds);

        if (userIds.Count == 0)
        {
            return [];
        }

        var wanted = userIds.ToArray();

        return await db.UserIdentities
            .AsNoTracking()
            .Where(identity => wanted.Contains(identity.UserId)
                               && identity.Status == UserStatuses.Active
                               && (identity.IdentityType == IdentityTypes.Phone
                                   || identity.IdentityType == IdentityTypes.Email))
            .OrderBy(identity => identity.Id)
            .Select(identity => new ConsumerContactRow(
                identity.UserId, identity.IdentityType, identity.IdentifierCiphertext))
            .ToListAsync(cancellationToken);
    }
}
