namespace UserSvc.Application.Ports.Tenancy;

/// <summary>
/// The delegation ceiling: which roles a given caller may hand out inside a given tenant. It is
/// resolved from the caller's own bindings, so an administrator can never grant more than they
/// hold.
/// </summary>
public interface IRoleDelegationService
{
    /// <summary>
    /// Role ids <paramref name="callerUserId"/> may assign within (<paramref name="tenantType"/>,
    /// <paramref name="tenantCode"/>).
    /// <para>
    /// Callers ask twice - once for the tenant code and once for the <c>*</c> sentinel - and use
    /// the union, because a whole-dimension administrator holds no member row in the target tenant
    /// and would otherwise resolve to an empty ceiling: allowed to add members, but refused every
    /// non-empty set of roles.
    /// </para>
    /// </summary>
    Task<IReadOnlySet<int>> DelegableRoleIdsAsync(
        int callerUserId, string tenantType, string tenantCode, CancellationToken cancellationToken);
}
