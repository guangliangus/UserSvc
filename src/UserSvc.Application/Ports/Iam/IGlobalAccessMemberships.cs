namespace UserSvc.Application.Ports.Iam;

/// <summary>
/// The membership mutations behind the two platform-level endpoints in this module. Their rows
/// belong to the tenant slice, so the transaction that touches them does too; what stays here is the
/// authority check, the role validation and the audit trail.
/// </summary>
public interface IGlobalAccessMemberships
{
    /// <summary>
    /// Give an account whole-dimension access: upsert its <c>*</c> membership as ACTIVE, replace its
    /// role bindings with <paramref name="roleIds"/>, re-derive the membership's administrator flag
    /// from those roles, and retire the account's specific memberships in the same dimension.
    /// <para>
    /// Within-dimension exclusivity is the point of that last step: holding "all companies" and
    /// company C001 at once makes the narrower row unreadable. Across dimensions the two are
    /// independent - "all companies" sits happily beside one specific supplier.
    /// </para>
    /// </summary>
    Task GrantWholeDimensionAsync(
        int userId,
        string tenantType,
        IReadOnlyCollection<int> roleIds,
        CancellationToken cancellationToken);

    /// <summary>Take whole-dimension access away: clear the <c>*</c> membership's roles, clear its
    /// administrator flag and mark it REMOVED. Specific memberships are untouched.</summary>
    Task RevokeWholeDimensionAsync(int userId, string tenantType, CancellationToken cancellationToken);

    /// <summary>
    /// Strip every non-removed membership from an account being promoted to platform super
    /// administrator, and report what was cleared so it can be written to the audit trail.
    /// <para>
    /// The last-administrator protection deliberately does not apply: leaving a tenant without an
    /// administrator here is the super administrator's own explicit decision.
    /// </para>
    /// </summary>
    Task<IReadOnlyList<ClearedMembership>> ClearAllMembershipsAsync(
        int userId,
        CancellationToken cancellationToken);
}

/// <summary>One membership taken away by a promotion, as it looked before.</summary>
public sealed record ClearedMembership(
    string TenantType,
    string TenantCode,
    bool ScopeAll,
    bool IsAdmin,
    IReadOnlyList<string> RoleCodes);
