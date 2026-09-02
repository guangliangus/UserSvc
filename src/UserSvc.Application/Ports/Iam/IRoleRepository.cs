using UserSvc.Domain.Iam;

namespace UserSvc.Application.Ports.Iam;

/// <summary>The role catalogue's persistence outlet (spec 2.1).</summary>
public interface IRoleRepository
{
    /// <summary>Insert and fill the generated id back in. A unique-code collision surfaces as the
    /// unit of work's conflict translation; the caller maps it to its own field-level answer.</summary>
    void Add(Role role);

    /// <summary>Whole catalogue, ordered by id. The role page needs every row even when the caller
    /// may only see some of them - the visibility narrowing happens above, on the full list, so a
    /// child's parent code can still be resolved for display.</summary>
    Task<IReadOnlyList<Role>> ListAllAsync(CancellationToken cancellationToken);

    Task<Role?> FindByIdAsync(int roleId, CancellationToken cancellationToken);

    /// <summary>Empty input answers an empty list without a round trip.</summary>
    Task<IReadOnlyList<Role>> FindByIdsAsync(IReadOnlyCollection<int> roleIds, CancellationToken cancellationToken);

    Task<IReadOnlyList<Role>> FindByCodesAsync(IReadOnlyCollection<string> codes, CancellationToken cancellationToken);

    /// <summary>Advisory only - a concurrent create can still land after the answer. The unique
    /// index is the actual guarantee; this exists so the form gets a field-level error.</summary>
    Task<bool> ExistsByCodeAsync(string code, CancellationToken cancellationToken);

    /// <summary>
    /// Case- and whitespace-insensitive duplicate-name probe, <b>scanning the whole catalogue</b>
    /// rather than the caller's visible slice: the platform super administrator sees every tenant's
    /// roles in one list, and two identically named rows are indistinguishable there.
    /// <para>
    /// <c>excludeRoleId</c> is the row being renamed, so an edit does not collide with itself; zero
    /// compares against every role.
    /// </para>
    /// </summary>
    Task<bool> ExistsByNameAsync(string name, int excludeRoleId, CancellationToken cancellationToken);

    /// <summary>Roles owned by one tenant. <c>SYSTEM</c> matches rows whose owner code is NULL,
    /// not rows whose owner code is empty.</summary>
    Task<IReadOnlyList<Role>> ListByOwnerAsync(
        string ownerType,
        string? ownerCode,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<Role>> ListChildrenAsync(
        IReadOnlyCollection<int> parentRoleIds,
        CancellationToken cancellationToken);

    /// <summary>
    /// Every descendant of the given roots, <b>excluding the roots themselves</b>, depth-capped at
    /// <see cref="IamConstants.MaxRoleSubtreeDepth"/> so a corrupted parent chain cannot loop.
    /// <para>
    /// The whole subtree, not just the direct children: the live tree is three deep, and stopping
    /// at one level would leave a <c>supplier_admin</c> holder unable to assign anything below
    /// <c>product_supplier_admin</c>.
    /// </para>
    /// </summary>
    Task<IReadOnlyList<Role>> ListDescendantsAsync(
        IReadOnlyCollection<int> rootRoleIds,
        CancellationToken cancellationToken);

    /// <summary>Delete guard: a role that still leads a group cannot go.</summary>
    Task<int> CountChildrenAsync(int roleId, CancellationToken cancellationToken);

    /// <summary>
    /// Hard delete. <c>role_menus</c>, <c>role_permissions</c> and the tenant bindings follow by
    /// foreign-key cascade. This is the one entity here that is physically removed - a soft-deleted
    /// role would keep its code occupied in a globally unique namespace forever.
    /// </summary>
    void Remove(Role role);
}
