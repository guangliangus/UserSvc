using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Ports.Tenancy;

/// <summary>One page of the tenant roster, plus the total the pager needs.</summary>
public sealed record TenantMemberPage(IReadOnlyList<TenantMember> Items, int Total);

/// <summary>
/// A roster query.
/// <para>
/// An empty <c>Status</c> means "everything except REMOVED" - the soft deleted rows stay hidden
/// unless asked for by name.
/// </para>
/// <para>
/// <c>UserIds</c> carries an already-resolved keyword search, and its three states are all
/// distinct: null is "no keyword", a populated list narrows the roster to those accounts, and an
/// <b>empty</b> list is "the keyword matched nobody" and must return no rows. Collapsing empty into
/// null is the bug this shape exists to prevent - it would answer a failed search with the entire
/// roster. The search itself lives in the account directory, because it matches an e-mail against
/// a blind index and a name fuzzily, neither of which this table knows anything about.
/// </para>
/// </summary>
public sealed record TenantMemberQuery(
    string TenantType,
    string TenantCode,
    string Status,
    IReadOnlyList<int>? UserIds,
    int Page,
    int PageSize);

/// <summary>
/// Persistence outlet for tenant memberships.
/// <para>
/// Two things are load-bearing across the whole interface. First, every lookup that matches on a
/// tenant code must exclude whole-dimension rows, because their code column carries the literal
/// <c>*</c> sentinel and would otherwise answer for a tenant nobody named. Second, lookups by
/// (user, tenant) return rows in <b>any</b> status: the caller needs the REMOVED row in order to
/// revive it rather than insert a duplicate the unique key would refuse.
/// </para>
/// </summary>
public interface ITenantMemberRepository
{
    void Add(TenantMember member);

    /// <summary>Any status, including REMOVED. Null when this person was never a member here.</summary>
    Task<TenantMember?> FindByUserAndTenantAsync(
        int userId, string tenantType, string tenantCode, CancellationToken cancellationToken);

    /// <summary>As above, under a row lock. Used by the admin-transfer path, which reads a member
    /// row and writes another in the same transaction and must not interleave with itself.</summary>
    Task<TenantMember?> FindByUserAndTenantForUpdateAsync(
        int userId, string tenantType, string tenantCode, CancellationToken cancellationToken);

    /// <summary>The lowest-id active administrator of a tenant, or null.</summary>
    Task<TenantMember?> FindAdminAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken);

    /// <summary>Every active administrator of a tenant, id ascending. A tenant may have several.</summary>
    Task<IReadOnlyList<TenantMember>> FindAdminsAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken);

    Task<IReadOnlyList<TenantMember>> ListActiveByUserAsync(int userId, CancellationToken cancellationToken);

    /// <summary>
    /// Memberships of several people at once, DISABLED rows included - an administrator has to see
    /// a suspended membership in order to reinstate it. REMOVED is the status that means "gone".
    /// </summary>
    Task<IReadOnlyList<TenantMember>> ListNonRemovedByUserIdsAsync(
        IReadOnlyCollection<int> userIds, CancellationToken cancellationToken);

    Task<TenantMemberPage> ListByTenantAsync(TenantMemberQuery query, CancellationToken cancellationToken);

    Task<int> CountActiveAdminsAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken);

    /// <summary>
    /// Serializes member writes for one tenant on a transaction-scoped advisory lock
    /// (<c>pg_advisory_xact_lock(hashtext('tenant:{type}:{code}'))</c>). <b>Must be called inside a
    /// transaction</b>: a transaction-scoped lock taken outside one is released immediately and
    /// silently, which looks exactly like working code until two administrators click at once.
    /// </summary>
    Task AcquireTenantLockAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken);

    /// <summary>Everyone with active access to this tenant, whole-dimension members included.</summary>
    Task<IReadOnlyList<int>> FindUserIdsByTenantCodeAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken);

    /// <summary>
    /// As above, narrowed to holders of one permission code. A separate method rather than an
    /// optional argument on purpose: an optional filter that can be forgotten will be forgotten,
    /// and forgetting this one silently widens the audience to every member of the tenant.
    /// The permission must be joined back through <b>this</b> membership - holding it in another
    /// company does not count.
    /// </summary>
    Task<IReadOnlyList<int>> FindUserIdsByCompanyCodeAndPermissionAsync(
        string companyCode, string permissionCode, CancellationToken cancellationToken);

    /// <summary>Administrators of several tenants at once. Group by code at the call site - one
    /// tenant can have more than one.</summary>
    Task<IReadOnlyList<TenantMember>> FindAdminsByTenantsAsync(
        string tenantType, IReadOnlyCollection<string> tenantCodes, CancellationToken cancellationToken);

    /// <summary>Active member counts per tenant code. Codes with no members are absent.</summary>
    Task<IReadOnlyDictionary<string, int>> CountActiveByTenantsAsync(
        string tenantType, IReadOnlyCollection<string> tenantCodes, CancellationToken cancellationToken);

    /// <summary>
    /// The notification roster for one tenant code, optionally narrowed to holders of given roles.
    /// Whole-dimension rows are <b>deliberately excluded</b>: they answer "who can see every
    /// tenant", which is the wrong audience for "tell this tenant's people something".
    /// </summary>
    Task<IReadOnlyList<TenantMember>> ListActiveMembersByTenantCodeAsync(
        string tenantCode, IReadOnlyCollection<string> roleCodes, int limit, CancellationToken cancellationToken);
}
