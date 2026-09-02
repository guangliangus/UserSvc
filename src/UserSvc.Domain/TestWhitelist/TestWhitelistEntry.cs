namespace UserSvc.Domain.TestWhitelist;

/// <summary>
/// One consumer account allowed to additionally see - and order - the test company's tour
/// products.
/// <para>
/// The verdict leaves this service as the <c>is_test</c> flag on token validation, which the
/// product and order services already call on every authenticated request. This service
/// deliberately does not know the test company's code: it answers only "is this account a test
/// user", and what that entitles them to see belongs to the services that sell things.
/// </para>
/// <para>
/// <b>The row is about a consumer account</b> (<c>identity.users</c>), which is why the table lives
/// in the consumer schema even though only a back-office operator ever writes it. The read side is
/// a consumer authentication path, and the foreign key is only expressible inside one schema.
/// </para>
/// <para>
/// Flat, like the rest of the consumer tables (decision 04): there is no invariant here that a
/// domain guard could hold better than the partial unique index
/// <c>uk_test_whitelist_users_active</c> does.
/// </para>
/// </summary>
public sealed class TestWhitelistEntry
{
    public int Id { get; set; }

    /// <summary>
    /// The consumer account id - <c>identity.users.id</c>, never a back-office account id.
    /// <para>
    /// The two realms are independent id sequences, so a list keyed on a bare id would let
    /// back-office account 5 inherit consumer account 5's membership. What keeps this column
    /// consumer-only is the write path resolving the id against <c>identity.users</c> before it
    /// stores anything, plus the foreign key behind it. The read path is realm-blind and will
    /// answer for any id it is handed, so a second caller of it has to carry that guard too.
    /// </para>
    /// </summary>
    public int UserId { get; set; }

    /// <summary>See <see cref="TestWhitelistStatuses"/>.</summary>
    public string Status { get; set; } = TestWhitelistStatuses.Active;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    /// <summary>Who added the entry. Kept because "when did this account become a tester, and on
    /// whose say-so" is the only question anybody asks of this table after the fact.</summary>
    public string CreatedBy { get; set; } = string.Empty;

    /// <summary>Who last changed the entry - in practice, who removed it.</summary>
    public string UpdatedBy { get; set; } = string.Empty;
}

/// <summary>
/// Statuses of a whitelist entry.
/// <para>
/// Removal is soft, for the same reason every other status column in this service is: the row is
/// the record that somebody was a tester between two dates, and a physical delete throws that away.
/// Re-adding a removed account revives its row rather than inserting a second one, which is what
/// the partial unique index on the ACTIVE rows requires.
/// </para>
/// </summary>
public static class TestWhitelistStatuses
{
    public const string Active = "ACTIVE";

    public const string Removed = "REMOVED";

    public static bool IsKnown(string? status) => status is Active or Removed;
}

/// <summary>
/// The audit vocabulary the whitelist writes. Parked here for the same reason as
/// <c>SupplierLinkAuditVocabulary</c> - the shared catalogue belongs to another slice's files.
/// </summary>
public static class TestWhitelistAuditVocabulary
{
    public const string AddAction = "TEST_WHITELIST_ADD";

    public const string RemoveAction = "TEST_WHITELIST_REMOVE";

    /// <summary>The target id is the consumer account id, as text.</summary>
    public const string TargetType = "test_whitelist";
}
