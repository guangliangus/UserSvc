using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>EF Core adapter for the menu registry.</summary>
public sealed class MenuRepository(UserSvcDbContext db) : IMenuRepository
{
    public void Add(Menu menu) => db.Menus.Add(menu);

    public void Remove(Menu menu) => db.Menus.Remove(menu);

    public Task<Menu?> FindByIdAsync(int menuId, CancellationToken cancellationToken) =>
        db.Menus.FirstOrDefaultAsync(menu => menu.Id == menuId, cancellationToken);

    public Task<Menu?> FindByCodeAsync(string code, CancellationToken cancellationToken) =>
        db.Menus.FirstOrDefaultAsync(menu => menu.Code == code, cancellationToken);

    public async Task<IReadOnlyList<Menu>> ListActiveAsync(CancellationToken cancellationToken) =>
        await Ordered(db.Menus.Where(menu => menu.Status == MenuStatuses.Active))
            .ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<Menu>> ListAllAsync(CancellationToken cancellationToken) =>
        await Ordered(db.Menus).ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<Menu>> ListByCodesAsync(
        IReadOnlyCollection<string> codes,
        CancellationToken cancellationToken)
    {
        if (codes.Count == 0)
        {
            return [];
        }

        return await Ordered(db.Menus.Where(menu => codes.Contains(menu.Code)))
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Menu>> ListByIdsAsync(
        IReadOnlyCollection<int> menuIds,
        CancellationToken cancellationToken)
    {
        if (menuIds.Count == 0)
        {
            return [];
        }

        return await Ordered(db.Menus.Where(menu => menuIds.Contains(menu.Id)))
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Menu>> ListChildrenAsync(int parentId, CancellationToken cancellationToken) =>
        await Ordered(db.Menus.Where(menu => menu.ParentId == parentId)).ToListAsync(cancellationToken);

    /// <summary>The sidebar's order is data. Id breaks ties so two menus sharing a sort order do not
    /// swap places between requests.</summary>
    private static IQueryable<Menu> Ordered(IQueryable<Menu> query) =>
        query.OrderBy(menu => menu.SortOrder).ThenBy(menu => menu.Id);
}
