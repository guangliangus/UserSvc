using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>A candidate owner of a role: the platform, or one named tenant.</summary>
public sealed record RoleOwner(string OwnerType, string? OwnerCode)
{
    /// <summary>The owner code flattened for display and for keying. A platform owner has none.</summary>
    public string Code => OwnerCode ?? string.Empty;

    /// <summary>Key used by <see cref="AdminScope.AdminRoleByOwner"/>. The <c>*</c> code is a real
    /// key here - it is how a whole-dimension membership is recorded.</summary>
    public string Key => OwnerType + "|" + Code;

    public static string KeyFor(string ownerType, string ownerCode) => ownerType + "|" + ownerCode;
}

/// <summary>
/// What one caller may do with roles, resolved from their memberships. The whole of role
/// administration reads this object rather than the token.
/// </summary>
public sealed class AdminScope
{
    private readonly List<Role> _adminRoles = [];
    private readonly List<RoleOwner> _owners = [];
    private readonly List<RoleOwner> _adminTenants = [];
    private readonly Dictionary<string, List<Role>> _adminRoleByOwner = new(StringComparer.Ordinal);

    /// <summary>
    /// The platform super administrator. Decided from the account row <b>before</b> any membership
    /// is read: the flag holds with zero memberships, so resolution short-circuits here with the
    /// platform as its only owner.
    /// </summary>
    public bool IsSuperAdmin { get; private set; }

    /// <summary>Every administrator role the caller holds anywhere, deduplicated. A fact about the
    /// person, not about this context - which is why narrowing to a dimension leaves it alone.</summary>
    public IReadOnlyList<Role> AdminRoles => _adminRoles;

    /// <summary>Owners the caller may create roles for. Narrowed by the acting context.</summary>
    public IReadOnlyList<RoleOwner> Owners => _owners;

    /// <summary>
    /// Every <b>specific</b> tenant the caller administers, never narrowed by the acting context and
    /// never including a whole-dimension sentinel row. This is the axis read visibility uses;
    /// <see cref="Owners"/> is the axis role ownership uses, and they are not the same question.
    /// </summary>
    public IReadOnlyList<RoleOwner> AdminTenants => _adminTenants;

    /// <summary>Administrator roles per owner key, including the <c>*</c> whole-dimension keys.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<Role>> AdminRoleByOwner =>
        _adminRoleByOwner.ToDictionary(pair => pair.Key, pair => (IReadOnlyList<Role>)pair.Value, StringComparer.Ordinal);

    /// <summary>The scope of a platform super administrator: everything, owned by the platform.</summary>
    public static AdminScope ForSuperAdmin()
    {
        var scope = new AdminScope { IsSuperAdmin = true };
        scope._owners.Add(new RoleOwner(RoleOwnerTypes.System, null));
        return scope;
    }

    /// <summary>The scope of someone who administers nothing. Not an error state - most callers
    /// resolve to this.</summary>
    public static AdminScope Empty() => new();

    internal void AddAdminRole(Role role)
    {
        if (!_adminRoles.Any(existing => existing.Id == role.Id))
        {
            _adminRoles.Add(role);
        }
    }

    internal void AddAdminRolesForOwner(string ownerKey, IEnumerable<Role> roles)
    {
        if (!_adminRoleByOwner.TryGetValue(ownerKey, out var bucket))
        {
            bucket = [];
            _adminRoleByOwner[ownerKey] = bucket;
        }

        bucket.AddRange(roles);
    }

    internal void AddOwner(RoleOwner owner)
    {
        if (!_owners.Any(existing => existing.OwnerType == owner.OwnerType && existing.Code == owner.Code))
        {
            _owners.Add(owner);
        }
    }

    internal void AddAdminTenant(RoleOwner owner)
    {
        if (!_adminTenants.Any(existing => existing.OwnerType == owner.OwnerType && existing.Code == owner.Code))
        {
            _adminTenants.Add(owner);
        }
    }

    /// <summary>Whether this owner is one the caller may write roles for.</summary>
    public bool HasOwner(RoleOwner owner) =>
        _owners.Any(candidate => candidate.OwnerType == owner.OwnerType && candidate.Code == owner.Code);

    /// <summary>
    /// The administrator roles that grant standing over this owner: the ones held through that exact
    /// tenant, plus the ones held through a whole-dimension membership of the same kind. Deduplicated
    /// by role id, because one role can be bound on both rows.
    /// </summary>
    public IReadOnlyList<Role> AdminRolesForOwner(RoleOwner owner)
    {
        var result = new List<Role>();
        var seen = new HashSet<int>();

        foreach (var key in new[] { owner.Key, RoleOwner.KeyFor(owner.OwnerType, IamConstants.ScopeAllSentinelCode) })
        {
            if (!_adminRoleByOwner.TryGetValue(key, out var roles))
            {
                continue;
            }

            foreach (var role in roles.Where(role => seen.Add(role.Id)))
            {
                result.Add(role);
            }
        }

        return result;
    }

    /// <summary>
    /// A copy keeping only the administrator roles in <paramref name="keep"/>.
    /// <para>
    /// An owner whose administrator roles are all dropped <b>disappears</b>. That is the mechanism
    /// that makes the role-management gate hold per owner rather than "passed somewhere, passes
    /// everywhere".
    /// </para>
    /// </summary>
    public AdminScope RetainRoles(ISet<int> keep)
    {
        var narrowed = new AdminScope { IsSuperAdmin = IsSuperAdmin };

        foreach (var role in _adminRoles.Where(role => keep.Contains(role.Id)))
        {
            narrowed._adminRoles.Add(role);
        }

        foreach (var (key, roles) in _adminRoleByOwner)
        {
            var kept = roles.Where(role => keep.Contains(role.Id)).ToList();
            if (kept.Count > 0)
            {
                narrowed._adminRoleByOwner[key] = kept;
            }
        }

        foreach (var owner in _owners.Where(owner => narrowed._adminRoleByOwner.ContainsKey(owner.Key)))
        {
            narrowed._owners.Add(owner);
        }

        narrowed._adminTenants.AddRange(_adminTenants);
        return narrowed;
    }

    /// <summary>
    /// Drop everything outside one owner type, in place.
    /// <para>
    /// A session that chose one dimension at sign-in administers only that side. The choice
    /// constrains what the session can <i>reach</i>, not merely what it can read - otherwise "all
    /// companies" would still be able to manage supplier members, and the isolation would exist only
    /// in the scope envelope. <see cref="AdminRoles"/> is untouched: it lists what the person holds,
    /// and every gate reads the per-owner map instead.
    /// </para>
    /// </summary>
    internal void RetainDimension(string ownerType)
    {
        var prefix = ownerType + "|";

        foreach (var key in _adminRoleByOwner.Keys.Where(key => !key.StartsWith(prefix, StringComparison.Ordinal)).ToList())
        {
            _adminRoleByOwner.Remove(key);
        }

        _owners.RemoveAll(owner => owner.OwnerType != ownerType);
        _adminTenants.RemoveAll(owner => owner.OwnerType != ownerType);
    }

    /// <summary>Keep exactly one owner - the tenant the caller is acting as.</summary>
    internal void RetainOwner(string ownerType, string ownerCode)
    {
        _owners.RemoveAll(owner => owner.OwnerType != ownerType || owner.Code != ownerCode);
    }
}
