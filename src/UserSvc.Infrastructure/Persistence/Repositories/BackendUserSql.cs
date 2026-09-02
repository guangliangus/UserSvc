namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// The two statements whose guard has to live inside the SQL, kept as constants so they can be read
/// - and asserted - without going through a database.
/// <para>
/// <b>Neither of these can be written as a read followed by a write.</b> Both enforce a rule about
/// the table as a whole ("some other active account still owns the platform"), and a rule about the
/// table cannot be checked by looking at one row in application memory: two callers each observing
/// two super administrators would each remove one, and the platform would be left with nobody who
/// can appoint a replacement. Putting the predicate in the WHERE clause makes the loser of that
/// race write zero rows, which the caller reports as a refusal.
/// </para>
/// <para>
/// Raw SQL rather than the query API for the same reason the architecture allows it at all: EF's
/// update builder cannot express "update this row only if a correlated subquery over the same table
/// holds", and splitting it into two round trips is precisely the bug.
/// </para>
/// </summary>
public static class BackendUserSql
{
    /// <summary>
    /// Clears the platform identity, but only while another <b>ACTIVE</b> account still holds it.
    /// <para>
    /// ACTIVE is not decoration: a disabled account cannot sign in, so counting it as "another
    /// super administrator" would let the platform end up owned only by someone who cannot use it.
    /// <c>AND is_super_admin</c> keeps the statement honest about what it did - it writes nothing
    /// when there was nothing to clear, so zero rows means "refused or already done" and the caller
    /// tells those apart by re-reading.
    /// </para>
    /// <para>Parameters: <c>{0}</c> the actor for the audit stamp, <c>{1}</c> the target id.</para>
    /// </summary>
    public const string RevokeSuperAdminIfAnotherActiveExists =
        """
        UPDATE iam.backend_users
        SET is_super_admin = false, updated_at = now(), updated_by = {0}
        WHERE id = {1} AND is_super_admin
          AND EXISTS (
            SELECT 1 FROM iam.backend_users o
            WHERE o.id <> {1} AND o.is_super_admin AND o.status = 'ACTIVE'
          )
        """;

    /// <summary>
    /// Moves an account's status, but only while another ACTIVE account holds the platform
    /// identity.
    /// <para>
    /// The same guard applied to the other way of removing the last platform owner. Revoking the
    /// flag and disabling the account that holds it have identical consequences - nobody can
    /// administer the platform - so guarding only the first would leave the second as an open door,
    /// including for the owner disabling themselves.
    /// </para>
    /// <para>Parameters: <c>{0}</c> the new status, <c>{1}</c> the actor, <c>{2}</c> the target id.</para>
    /// </summary>
    public const string SetStatusIfAnotherActiveSuperAdminExists =
        """
        UPDATE iam.backend_users
        SET status = {0}, updated_at = now(), updated_by = {1}
        WHERE id = {2}
          AND EXISTS (
            SELECT 1 FROM iam.backend_users o
            WHERE o.id <> {2} AND o.is_super_admin AND o.status = 'ACTIVE'
          )
        """;

    /// <summary>
    /// The accounts a scoped caller may see, read from the tenant membership table.
    /// <para>
    /// <b><c>NOT scope_all</c> on the specific-tenant branch is the load-bearing clause.</b> A
    /// whole-dimension membership - "all companies" - is stored as a row like any other, so without
    /// that predicate an administrator of one company would see every account holding platform-wide
    /// company access, simply because such an account technically belongs to their tenant too. The
    /// whole-dimension branch above it is how a caller who genuinely administers the dimension sees
    /// those rows.
    /// </para>
    /// <para>
    /// It is raw SQL because the tenant tables belong to a module this service has not modelled
    /// yet; when they arrive as entities, this becomes an ordinary subquery and the shape does not
    /// change. <c>AS "Value"</c> is what EF's scalar query API expects the column to be called.
    /// </para>
    /// <para>
    /// Parameters: <c>{0}</c> the whole dimensions, <c>{1}</c> the tenant types, <c>{2}</c> the
    /// matching tenant codes - the last two positionally paired.
    /// </para>
    /// </summary>
    public const string VisibleUserIds =
        """
        SELECT DISTINCT m.user_id AS "Value"
        FROM iam.tenant_members m
        WHERE m.status = 'ACTIVE'
          AND (
            m.tenant_type = ANY({0}::text[])
            OR (
              NOT m.scope_all
              AND EXISTS (
                SELECT 1 FROM unnest({1}::text[], {2}::text[]) AS t(tenant_type, tenant_code)
                WHERE t.tenant_type = m.tenant_type AND t.tenant_code = m.tenant_code
              )
            )
          )
        """;
}
