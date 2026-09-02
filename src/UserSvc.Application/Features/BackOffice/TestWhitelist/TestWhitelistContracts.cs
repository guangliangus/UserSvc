using UserSvc.Application.Features.BackOffice.Consumers;

namespace UserSvc.Application.Features.BackOffice.TestWhitelist;

/// <summary>
/// One page of the test-user whitelist.
/// <para>
/// Items are ordered by consumer account id, which is what makes paging stable: the underlying
/// query sorts, so a page boundary cannot repeat or skip an entry between two requests.
/// </para>
/// </summary>
public sealed record TestWhitelistListResponse
{
    /// <summary>Never null. An empty list is a whitelist with nobody on it, which is the normal
    /// state of a fresh deployment.</summary>
    public IReadOnlyList<ConsumerSummaryResponse> Items { get; init; } = [];

    /// <summary>Whitelisted accounts in total, unpaged.</summary>
    public required int Total { get; init; }

    public required int Page { get; init; }

    public required int PageSize { get; init; }

    /// <summary>Page count at this page size; zero when the whitelist is empty.</summary>
    public required int TotalPages { get; init; }
}

/// <summary>
/// Add one consumer account to the whitelist.
/// <para>
/// Idempotent: adding an account that is already on the list succeeds and changes nothing.
/// </para>
/// </summary>
public sealed record AddTestWhitelistRequest
{
    /// <summary>
    /// A consumer account id - <c>identity.users.id</c>. Resolve a phone number or an email address
    /// to one with <c>GET /back-office/consumers/lookup</c> first; a back-office account id is not
    /// a valid value here even though it is the same kind of number.
    /// </summary>
    public required int UserId { get; init; }
}

/// <summary>
/// The state of one whitelist entry, as the audit trail records it. Property names become the keys
/// of the stored JSON, and the writer spells them in snake case.
/// </summary>
internal sealed record TestWhitelistAuditSnapshot(int UserId, string Status);
