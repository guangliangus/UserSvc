using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// The two standing questions the tenant slice asks, answered from the database on every call.
/// <para>
/// <b>This one does not delegate to <c>AdminScopeService</c>, and the difference is not
/// cosmetic.</b> That service resolves the scope of <i>the caller of the current request</i>: it
/// takes an <c>IBackOfficeCaller</c> and narrows the answer to the acting context carried in that
/// caller's token. This port asks about an account id with no acting context at all, and the tenant
/// slice uses it to reason about people other than the caller. Routing it through the ambient
/// caller would answer a question about one account with another account's standing, so the gate is
/// computed here from the two rows that define it.
/// </para>
/// <para>
/// It is the same rule the role slice enforces - spec 3.3's <c>assertCanManageMembers</c> - read
/// off the membership's derived <c>is_admin</c> flag rather than by re-deriving it from the role
/// bindings. That flag is maintained on every write precisely so this question costs one query.
/// </para>
/// </summary>
public sealed class AdminStandingService(
    IBackOfficeUserDirectory users,
    ITenantMemberRepository members) : IAdminStandingService
{
    /// <summary>
    /// A non-positive id and a missing row both answer false. "Not a super administrator" is the
    /// safe answer to a malformed question, and it is also the true one.
    /// </summary>
    public async Task<bool> IsPlatformSuperAdminAsync(int userId, CancellationToken cancellationToken)
    {
        if (userId <= 0)
        {
            return false;
        }

        var flags = await users.FindFlagsAsync(userId, cancellationToken);
        return flags?.IsSuperAdmin ?? false;
    }

    /// <summary>
    /// Gate R3. Only ACTIVE memberships are considered - a disabled member administers nothing -
    /// and a whole-dimension row counts for every tenant of its dimension, which is what
    /// <see cref="TenantMember.Covers"/> already encodes.
    /// </summary>
    public async Task<bool> CanManageMembersAsync(
        int callerUserId, string tenantType, string tenantCode, CancellationToken cancellationToken)
    {
        if (callerUserId <= 0)
        {
            return false;
        }

        if (await IsPlatformSuperAdminAsync(callerUserId, cancellationToken))
        {
            return true;
        }

        var memberships = await members.ListActiveByUserAsync(callerUserId, cancellationToken);
        return memberships.Any(member => member.IsAdmin && member.Covers(tenantType, tenantCode));
    }
}
