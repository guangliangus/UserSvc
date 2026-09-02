using UserSvc.Domain.Iam;

namespace UserSvc.Application.Ports.Iam;

/// <summary>The menu registry's persistence outlet (spec 2.3). Every list is ordered by
/// <c>sort_order</c> then id - the sidebar's order is data, not a client-side decision.</summary>
public interface IMenuRepository
{
    void Add(Menu menu);

    Task<Menu?> FindByIdAsync(int menuId, CancellationToken cancellationToken);

    Task<Menu?> FindByCodeAsync(string code, CancellationToken cancellationToken);

    /// <summary>ACTIVE rows only - the per-user sidebar must never surface a soft-deleted menu.</summary>
    Task<IReadOnlyList<Menu>> ListActiveAsync(CancellationToken cancellationToken);

    /// <summary>Every status, for the management tree.</summary>
    Task<IReadOnlyList<Menu>> ListAllAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<Menu>> ListByCodesAsync(
        IReadOnlyCollection<string> codes,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<Menu>> ListByIdsAsync(
        IReadOnlyCollection<int> menuIds,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<Menu>> ListChildrenAsync(int parentId, CancellationToken cancellationToken);

    /// <summary>Hard delete. Grants cascade; child menus and permission points do not (RESTRICT),
    /// so the caller must refuse a menu that still has children and delete its points first.</summary>
    void Remove(Menu menu);
}
