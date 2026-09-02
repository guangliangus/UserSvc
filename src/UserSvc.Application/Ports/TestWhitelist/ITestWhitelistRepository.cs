using UserSvc.Domain.TestWhitelist;

namespace UserSvc.Application.Ports.TestWhitelist;

/// <summary>
/// Persistence outlet for the consumer test-user whitelist. There is a database on the other side,
/// so it is a port.
/// <para>
/// <b>Every method here is realm-blind</b>: it compares whatever account id it is handed against
/// the table. Keeping the list consumer-only is the write path's job - it resolves the id against
/// <c>identity.users</c> first - and the read path's, which must not be called for a back-office
/// subject. See <see cref="TestWhitelistEntry.UserId"/> for why a bare id cannot tell the two
/// realms apart.
/// </para>
/// </summary>
public interface ITestWhitelistRepository
{
    /// <summary>Stages a new entry for the next save.</summary>
    void Add(TestWhitelistEntry entry);

    /// <summary>
    /// Whether this account is currently whitelisted.
    /// <para>
    /// Its own method rather than a call to <see cref="FindAsync"/>, because the caller behind it
    /// is token validation - the hottest authenticated path in the platform - and it wants one
    /// indexed existence check, not a row.
    /// </para>
    /// </summary>
    Task<bool> IsWhitelistedAsync(int userId, CancellationToken cancellationToken);

    /// <summary>
    /// This account's entry whatever its status, or null when it never had one. <b>Tracked</b>: the
    /// two callers either revive it or retire it, and a REMOVED row is exactly the one an add must
    /// find - reviving it is what the unique index on the ACTIVE rows requires.
    /// </summary>
    Task<TestWhitelistEntry?> FindAsync(int userId, CancellationToken cancellationToken);

    /// <summary>
    /// Every whitelisted account id, ascending.
    /// <para>
    /// Sorted in the database, and the order is part of the contract: it is what makes paging
    /// stable, so a page boundary cannot repeat or skip an entry between two requests.
    /// </para>
    /// <para>
    /// Unpaged on purpose. The list is expected to hold a couple of dozen ids, the endpoint that
    /// reads it needs the true total anyway, and the page it hands back is a slice of this - so
    /// pushing the paging down would buy nothing and cost the total a second query.
    /// </para>
    /// </summary>
    Task<IReadOnlyList<int>> ListActiveUserIdsAsync(CancellationToken cancellationToken);
}
