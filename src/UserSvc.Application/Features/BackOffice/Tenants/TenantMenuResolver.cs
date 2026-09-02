using UserSvc.Application.Ports.Tenancy;

namespace UserSvc.Application.Features.BackOffice.Tenants;

/// <summary>
/// Turns the menu ids a set of roles grants into the menu codes a context may see. Pure set work
/// over rows the caller already read, so it is not a port.
/// </summary>
public static class TenantMenuResolver
{
    /// <summary>
    /// <b>The audience filter is switched off, deliberately.</b>
    /// <para>
    /// It used to narrow a context's menus to those whose audience covers the kind of tenant being
    /// acted in. With it off, a member sees every menu their roles grant, in any tenant kind. That
    /// is a <i>visibility</i> narrowing rather than an authorization boundary - which routes may
    /// actually be entered is decided by permission codes, and that is untouched - so switching it
    /// off widened what the sidebar renders and nothing else.
    /// </para>
    /// <para>
    /// It is a flag rather than deleted code because restoring it has to happen in <b>two</b>
    /// places, and forgetting the second is the classic way this comes back broken: filtered
    /// parents leak back in through the ancestor climb below. Both sites read this field.
    /// </para>
    /// </summary>
    private static readonly bool AudienceGateEnabled = false;

    /// <summary>
    /// Resolves granted menu ids against the live catalogue.
    /// </summary>
    /// <returns>
    /// The codes to render, sorted, and the ids that survived - the second half is what the
    /// permission resolver needs, so that a permission hanging off a menu that was soft-deleted
    /// falls with it.
    /// </returns>
    public static (IReadOnlyList<string> Codes, IReadOnlySet<int> KeptIds) Resolve(
        IReadOnlyCollection<int> grantedMenuIds,
        IReadOnlyList<MenuRecord> activeMenus,
        string tenantType)
    {
        ArgumentNullException.ThrowIfNull(activeMenus);

        if (grantedMenuIds is null || grantedMenuIds.Count == 0)
        {
            return ([], new HashSet<int>());
        }

        var byId = activeMenus.ToDictionary(menu => menu.Id);
        var kept = new HashSet<int>();

        foreach (var id in grantedMenuIds)
        {
            // Not in the active catalogue: inactive or gone. Its permission points go with it.
            if (!byId.TryGetValue(id, out var menu))
            {
                continue;
            }

            if (AudienceGateEnabled && !menu.Audience.Contains(tenantType))
            {
                continue;
            }

            kept.Add(id);
        }

        // A granted child must never render without the group it hangs under, so every ancestor
        // comes along. When the gate is restored, an ancestor whose audience does not cover this
        // tenant kind contributes no code of its own but the climb continues past it - stopping
        // there would drop the grandparent that does belong.
        foreach (var id in kept.ToList())
        {
            var current = byId[id].ParentId;
            var guard = 0;

            while (current is { } parentId && byId.TryGetValue(parentId, out var parent) && guard++ < 64)
            {
                kept.Add(parentId);
                current = parent.ParentId;
            }
        }

        var codes = kept
            .Where(id => byId.ContainsKey(id))
            .Where(id => !AudienceGateEnabled || byId[id].Audience.Contains(tenantType))
            .Select(id => byId[id].Code)
            .Order(StringComparer.Ordinal)
            .ToList();

        return (codes, kept);
    }
}
