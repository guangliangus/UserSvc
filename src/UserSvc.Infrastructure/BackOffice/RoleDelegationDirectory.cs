using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Ports.Tenancy;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// The delegation ceiling, over the RBAC slice's own delegation service.
/// <para>
/// The two shapes line up exactly - same four arguments, same meaning - and differ only in the
/// collection type, so this adapter is a set conversion and a name. What it deliberately does
/// <b>not</b> do is call the service's <c>DelegableRoleSetAsync</c>, which takes the union over the
/// tenant code and the whole-dimension sentinel itself: the tenant slice asks the two questions
/// separately and unions them at its own call site, and answering a single-tenant question with a
/// pre-unioned set would silently widen every ceiling this port hands out.
/// </para>
/// </summary>
public sealed class RoleDelegationDirectory(RoleDelegationService delegation) : IRoleDelegationService
{
    public async Task<IReadOnlySet<int>> DelegableRoleIdsAsync(
        int callerUserId, string tenantType, string tenantCode, CancellationToken cancellationToken) =>
        new HashSet<int>(
            await delegation.DelegableRoleIdsAsync(callerUserId, tenantType, tenantCode, cancellationToken));
}
