using UserSvc.Domain.Suppliers;

namespace UserSvc.Application.Ports.Suppliers;

/// <summary>
/// Persistence outlet for supplier-to-company mountings. There is a database on the other side, so
/// it is a port.
/// <para>
/// Every read here is ACTIVE-only. UNLINKED rows are history: they exist so that "who was this
/// supplier mounted onto last March" has an answer, and letting one back into a read would make a
/// retired mounting behave like a live one.
/// </para>
/// <para>
/// <b>There is no ListAll.</b> The Go original carries one for a link-history view that no endpoint
/// exposes; porting an unreachable read would put a paged query into the contract with nothing to
/// hold it honest. It arrives with the history endpoint, if that is ever built.
/// </para>
/// </summary>
public interface ISupplierCompanyLinkRepository
{
    /// <summary>Stages a new mounting for the next save. The caller's unit of work decides when it
    /// lands, which is what lets a relink retire the old row and insert this one atomically.</summary>
    void Add(SupplierCompanyLink link);

    /// <summary>
    /// The single ACTIVE mounting of one supplier, or null when it is independent - which is a
    /// normal state and never an error.
    /// <para>
    /// <b>Untracked.</b> Neither caller writes through it: both read the company code off it, and
    /// the retirement itself goes through <see cref="UnlinkActiveBySupplierAsync"/>, which is a
    /// set-based statement the change tracker knows nothing about. Handing out a tracked row beside
    /// that statement is how a tracker ends up holding a version of the row the database no longer
    /// has.
    /// </para>
    /// <para>
    /// There is no row lock and must not be one. <c>uk_supplier_links_active</c> is the invariant,
    /// and a racing double mount is meant to surface as a unique violation rather than to be
    /// serialized behind a lock that every read would then pay for.
    /// </para>
    /// </summary>
    Task<SupplierCompanyLink?> FindActiveBySupplierAsync(
        string supplierCode, CancellationToken cancellationToken);

    /// <summary>
    /// Retires the supplier's ACTIVE mounting - one <c>UPDATE ... WHERE status = 'ACTIVE'</c> - and
    /// answers how many rows it touched: <b>0 when there was nothing mounted</b>.
    /// <para>
    /// <b>The count is the decision, not a statistic.</b> It is what makes an unmount idempotent
    /// without a read-then-write race: two operators unmounting the same supplier at once both see
    /// an ACTIVE row, and only the one whose statement actually changed it writes the audit row and
    /// retires the affected tokens. A tracked mutation would have both of them do it.
    /// </para>
    /// <para>
    /// Set-based for a second reason: it is <b>replayable</b>. The unit of work runs a transaction
    /// inside PostgreSQL's transient-failure retry strategy, which re-executes the whole body from
    /// a clean transaction; a statement re-applies on that second pass, whereas a change-tracker
    /// entry whose changes were already accepted would silently not.
    /// </para>
    /// <para>
    /// The timestamp and the actor are passed in rather than read here: this is a persistence
    /// port, and what time it is - and who is asking - are the application layer's to know.
    /// </para>
    /// </summary>
    Task<int> UnlinkActiveBySupplierAsync(
        string supplierCode,
        DateTimeOffset timestamp,
        string actor,
        CancellationToken cancellationToken);

    /// <summary>
    /// The ACTIVE mountings of many suppliers at once, supplier code ascending. This is the merge
    /// source of the supplier-link listing, which would otherwise be one query per supplier.
    /// <para>
    /// An empty input answers empty <b>without touching the database</b>: an <c>IN ()</c> built
    /// from nothing matches nothing, so the round trip is knowably pointless.
    /// </para>
    /// </summary>
    Task<IReadOnlyList<SupplierCompanyLink>> ListActiveBySuppliersAsync(
        IReadOnlyList<string> supplierCodes, CancellationToken cancellationToken);

    /// <summary>Every supplier mounted onto one company, supplier code ascending.</summary>
    Task<IReadOnlyList<SupplierCompanyLink>> ListActiveByCompanyAsync(
        string companyCode, CancellationToken cancellationToken);
}
