using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Suppliers;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Suppliers;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// EF Core adapter for supplier-to-company mountings, over the shared persistence context - so a
/// relink's two statements and the audit row that explains them commit under one transaction.
/// <para>
/// <b>It implements two ports on purpose.</b>
/// <see cref="ISupplierCompanyLinkRepository"/> is this slice's own read and write outlet;
/// <see cref="ISupplierCompanyLinkDirectory"/> is the narrow question the tenancy slice asks on
/// every context resolution ("which suppliers hang off this company", "which company does this
/// supplier hang under"). They are one table and one set of rules about which rows count, and
/// splitting them across two adapters is how the two would eventually disagree about whether an
/// UNLINKED row is still a mounting. The directory half is the reason this table's arrival is a
/// cutover for the tenancy slice too: it replaces a placeholder that answered "no mountings" to
/// everything.
/// </para>
/// <para>
/// Every query filters to ACTIVE. UNLINKED rows exist so that "who was this supplier mounted onto
/// before" has an answer, and letting one into a read would give a retired mounting live authority.
/// </para>
/// </summary>
public sealed class SupplierCompanyLinkRepository(UserSvcDbContext db)
    : ISupplierCompanyLinkRepository, ISupplierCompanyLinkDirectory
{
    /// <summary>
    /// Reached through <c>DbContext.Set&lt;T&gt;()</c> rather than a <c>DbSet</c> property on
    /// the context. The entity is mapped by its configuration, which the context discovers from the
    /// assembly, so the property would be convenience only - and the context is shared by every
    /// slice, which makes it the file to touch least.
    /// </summary>
    private DbSet<SupplierCompanyLink> Links => db.Set<SupplierCompanyLink>();

    public void Add(SupplierCompanyLink link) => Links.Add(link);

    /// <summary>Untracked: nothing writes through it, and the retirement below bypasses the change
    /// tracker entirely. See the port.</summary>
    public Task<SupplierCompanyLink?> FindActiveBySupplierAsync(
        string supplierCode, CancellationToken cancellationToken) =>
        Links
            .AsNoTracking()
            .FirstOrDefaultAsync(
                link => link.SupplierCode == supplierCode
                        && link.Status == SupplierCompanyLinkStatuses.Active,
                cancellationToken);

    /// <summary>
    /// One <c>UPDATE ... WHERE supplier_code = @code AND status = 'ACTIVE'</c>, answering the rows
    /// it touched. It runs on the context's connection, so it joins whatever transaction the caller
    /// opened.
    /// <para>
    /// It bypasses the change tracker by design - that is what makes it replayable under the retry
    /// strategy and what makes the affected count trustworthy - which is also why
    /// <see cref="FindActiveBySupplierAsync"/> above hands out an untracked row: a tracked one
    /// would survive this statement holding the pre-update values.
    /// </para>
    /// </summary>
    public Task<int> UnlinkActiveBySupplierAsync(
        string supplierCode,
        DateTimeOffset timestamp,
        string actor,
        CancellationToken cancellationToken) =>
        Links
            .Where(link => link.SupplierCode == supplierCode
                           && link.Status == SupplierCompanyLinkStatuses.Active)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(link => link.Status, SupplierCompanyLinkStatuses.Unlinked)
                    .SetProperty(link => link.UpdatedAt, timestamp)
                    .SetProperty(link => link.UpdatedBy, actor),
                cancellationToken);

    public async Task<IReadOnlyList<SupplierCompanyLink>> ListActiveBySuppliersAsync(
        IReadOnlyList<string> supplierCodes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(supplierCodes);

        if (supplierCodes.Count == 0)
        {
            // An IN () built from nothing matches nothing, so the round trip is knowably pointless.
            return [];
        }

        var wanted = supplierCodes.ToArray();

        return await Links
            .AsNoTracking()
            .Where(link => wanted.Contains(link.SupplierCode)
                           && link.Status == SupplierCompanyLinkStatuses.Active)
            .OrderBy(link => link.SupplierCode)
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// No empty-input guard, unlike its batch sibling: a blank company code is filtered out by the
    /// caller, and a query for one is a legitimate way to learn there are no such rows.
    /// <para>
    /// The ORDER BY belongs to PostgreSQL and must stay there. Sorting a text column in .NET
    /// applies the host's culture rules, which order differently from the database collation - so
    /// the list would silently depend on where it was sorted.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<SupplierCompanyLink>> ListActiveByCompanyAsync(
        string companyCode, CancellationToken cancellationToken) =>
        await Links
            .AsNoTracking()
            .Where(link => link.CompanyCode == companyCode
                           && link.Status == SupplierCompanyLinkStatuses.Active)
            .OrderBy(link => link.SupplierCode)
            .ToListAsync(cancellationToken);

    /// <summary>
    /// The tenancy slice's read. Untracked and projected to codes: it runs on every company context
    /// resolution, and it has no business handing an entity anybody could write back.
    /// </summary>
    public async Task<IReadOnlyList<string>> ListSupplierCodesByCompanyAsync(
        string companyCode, CancellationToken cancellationToken) =>
        await Links
            .AsNoTracking()
            .Where(link => link.CompanyCode == companyCode
                           && link.Status == SupplierCompanyLinkStatuses.Active)
            .OrderBy(link => link.SupplierCode)
            .Select(link => link.SupplierCode)
            .ToListAsync(cancellationToken);

    /// <summary>
    /// The company one supplier hangs under, or null when it is independent - the conservative
    /// default the port documents, and never an error. <c>uk_supplier_links_active</c> guarantees
    /// there is at most one answer, so this needs no ordering to be deterministic.
    /// </summary>
    public Task<string?> FindCompanyCodeBySupplierAsync(
        string supplierCode, CancellationToken cancellationToken) =>
        Links
            .AsNoTracking()
            .Where(link => link.SupplierCode == supplierCode
                           && link.Status == SupplierCompanyLinkStatuses.Active)
            .Select(link => link.CompanyCode)
            .FirstOrDefaultAsync(cancellationToken);
}
