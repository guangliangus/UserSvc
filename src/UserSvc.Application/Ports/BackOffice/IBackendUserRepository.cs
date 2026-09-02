using UserSvc.Domain.BackOffice;

namespace UserSvc.Application.Ports.BackOffice;

/// <summary>
/// Back-office accounts. A database sits behind it, so it is a port.
/// <para>
/// <b>Three of these methods carry their guard inside a single SQL statement</b>
/// (<see cref="RevokeSuperAdminIfAnotherActiveExistsAsync"/>,
/// <see cref="SetStatusIfAnotherActiveSuperAdminExistsAsync"/> and
/// <see cref="IncrementTokenVersionAsync"/>). That is not a performance choice. A read-then-write
/// version of the first two lets two concurrent callers each observe "there are two super
/// administrators" and each remove one, leaving a platform with no owner and no way to appoint
/// another; putting the predicate in the WHERE clause makes the loser of that race write nothing.
/// </para>
/// <para>
/// <b>Where the rest of this codebase would mutate a tracked entity, do that instead.</b> EF tracks
/// changes per property, so setting one field and saving writes one column - the "an update wrote
/// every column back, including the stale ones" hazard that the Go original worked around does not
/// exist here. The explicit single-column methods below remain because their <i>guard</i> or their
/// <i>omission</i> is the point, not because writing one column needs a method.
/// </para>
/// </summary>
public interface IBackendUserRepository
{
    /// <summary>
    /// Stages a new account, with any identities attached to it, for the next save.
    /// <para>
    /// <b>Nothing that maps a request onto a <see cref="BackendUser"/> may set
    /// <see cref="BackendUser.IsSuperAdmin"/>.</b> The insert carries the property's default, which
    /// is false; the flag has exactly one write path, and it is
    /// <see cref="GrantSuperAdminAsync"/>. A creation path that could carry it would mean any
    /// endpoint able to create an account is also able to create an owner of the platform.
    /// </para>
    /// </summary>
    void Add(BackendUser user);

    /// <summary>
    /// The account with this id, tracked so the caller can change it, or null.
    /// <b>No status filter</b> - a disabled account still has to be readable, or nothing could ever
    /// re-enable it.
    /// </summary>
    Task<BackendUser?> FindByIdAsync(int id, CancellationToken cancellationToken);

    /// <summary>
    /// A fresh, untracked snapshot of one account, or null.
    /// <para>
    /// <b>Not a duplicate of <see cref="FindByIdAsync"/>, and the difference is load-bearing.</b>
    /// A tracked read returns whatever instance this unit of work already has, without refreshing
    /// it from the database - which is right for a caller about to change the row, and wrong for
    /// one deciding what just happened. After a guarded statement writes through raw SQL, a tracked
    /// re-read hands back the pre-write values and the caller concludes the opposite of the truth:
    /// a revocation that actually succeeded reads as refused, or the reverse. Use this whenever the
    /// answer, rather than the entity, is what matters.
    /// </para>
    /// </summary>
    Task<BackendUser?> ReadByIdAsync(int id, CancellationToken cancellationToken);

    /// <summary>
    /// The accounts with these ids, in no particular order and with no status filter. An id with no
    /// row is simply absent from the result - a dangling reference is the caller's to interpret,
    /// and for the callers that batch-resolve names it means "skip this row", not "fail".
    /// </summary>
    Task<IReadOnlyList<BackendUser>> ListByIdsAsync(IReadOnlyList<int> ids, CancellationToken cancellationToken);

    /// <summary>
    /// One page of the back-office directory, newest first, plus the unpaged total.
    /// <para>
    /// <paramref name="visibility"/> decides which accounts exist as far as this caller is
    /// concerned, and its three states are all meaningful: <b>null</b> is unrestricted and belongs
    /// to the platform super administrator alone; a filter naming dimensions or tenants restricts
    /// to those; and a filter naming <b>neither</b> matches nobody - the correct answer for a
    /// caller who administers nothing, and the reason it must not be conflated with null.
    /// </para>
    /// <para>
    /// The filter is a separate argument rather than a field on <paramref name="query"/> because
    /// that record is bound from the request. A visibility field on a request-bound type is a
    /// client-settable one, which is to say no filter at all.
    /// </para>
    /// </summary>
    Task<BackOfficeUserPage> ListAsync(
        BackOfficeUserQuery query,
        UserVisibilityFilter? visibility,
        CancellationToken cancellationToken);

    /// <summary>
    /// The people-picker: active accounts only, id ascending, capped at twenty unless a specific
    /// id was asked for.
    /// <para>
    /// <paramref name="visibility"/> means the same three things as in <see cref="ListAsync"/> and
    /// matters more here, because this endpoint carries no permission requirement of its own.
    /// Unfiltered, it answered name searches across every back-office account on the platform and
    /// confirmed any account's existence and display name from a bare id.
    /// </para>
    /// </summary>
    /// <param name="userId">A specific account to resolve, or 0 for "no id given". Positive values
    /// bypass the name search and the cap - it is a lookup, not a search.</param>
    /// <param name="nickname">Substring to match against every spelling of the display name. Only
    /// consulted when <paramref name="userId"/> is not positive.</param>
    /// <param name="visibility">Which accounts exist as far as this caller is concerned; see the
    /// summary.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    Task<IReadOnlyList<BackOfficeUserOption>> ListOptionsAsync(
        int userId,
        string? nickname,
        UserVisibilityFilter? visibility,
        CancellationToken cancellationToken);

    /// <summary>
    /// Writes <c>status</c> and nothing else. False means no row matched, which the caller reports
    /// as a missing account.
    /// <para>
    /// <b>Not for a super administrator leaving ACTIVE</b> - that path must go through
    /// <see cref="SetStatusIfAnotherActiveSuperAdminExistsAsync"/>, or disabling the last one is a
    /// plain update away.
    /// </para>
    /// </summary>
    Task<bool> UpdateStatusAsync(int id, string status, string actor, CancellationToken cancellationToken);

    /// <summary>Writes <c>password_hash</c> and nothing else. False means no row matched.</summary>
    Task<bool> UpdatePasswordHashAsync(
        int id,
        string passwordHash,
        string actor,
        CancellationToken cancellationToken);

    /// <summary>
    /// <c>token_version = token_version + 1</c> for each id, which instantly invalidates every
    /// access token those accounts are holding. Unknown ids are ignored, so it is idempotent and
    /// safe to call with a set assembled optimistically.
    /// <para>
    /// <b>It deliberately leaves <c>updated_at</c> and <c>updated_by</c> alone.</b> The bump is a
    /// side effect of somebody else's decision - a password reset, a promotion - and stamping this
    /// row's audit columns with that actor would misattribute a change nobody made to the account
    /// itself. Who did it belongs in the audit log.
    /// </para>
    /// <para>
    /// Safe inside a transaction. Any cache built on the version must be invalidated <b>after</b>
    /// that transaction commits: dropping the cached value first opens a window where a reader
    /// repopulates it from the not-yet-committed old row, and the bump then has no effect at all.
    /// </para>
    /// </summary>
    Task IncrementTokenVersionAsync(IReadOnlyList<int> ids, CancellationToken cancellationToken);

    /// <summary>
    /// The same bump for every back-office account, returning how many rows moved. The
    /// force-everyone-to-reissue lever; keep it behind an endpoint that is hard to press by
    /// accident.
    /// </summary>
    Task<int> IncrementTokenVersionForEveryAccountAsync(CancellationToken cancellationToken);

    /// <summary>Every account's current token version, for a cache republish.</summary>
    Task<IReadOnlyList<BackendUserTokenVersion>> ListTokenVersionsAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Sets <c>is_super_admin</c> to true. False means no row matched.
    /// <para>
    /// <b>Grant only.</b> There is no matching plain revoke, and that asymmetry is the design:
    /// removing the flag has to answer "is there another one left", which only
    /// <see cref="RevokeSuperAdminIfAnotherActiveExistsAsync"/> can do without a race.
    /// </para>
    /// </summary>
    Task<bool> GrantSuperAdminAsync(int id, string actor, CancellationToken cancellationToken);

    /// <summary>
    /// Clears <c>is_super_admin</c> only while some <b>other ACTIVE</b> account still holds it.
    /// True means the flag was cleared.
    /// <para>
    /// "Another super administrator" counts ACTIVE accounts only, on purpose: a disabled account
    /// cannot sign in, so it cannot stand in for a usable platform owner.
    /// </para>
    /// <para>
    /// False is <b>not</b> only "refused". It is also the answer when the target held no flag to
    /// begin with, because a statement that writes nothing cannot tell the two apart - so a caller
    /// that wants to distinguish "you may not" from "already done" must compare against a read of
    /// the target taken before the call. Getting that backwards turns a lost race, which is an
    /// idempotent success, into a refusal the operator cannot explain.
    /// </para>
    /// </summary>
    Task<bool> RevokeSuperAdminIfAnotherActiveExistsAsync(
        int id,
        string actor,
        CancellationToken cancellationToken);

    /// <summary>
    /// Writes <c>status</c> only while some other ACTIVE account holds the super-administrator
    /// flag. True means the status was written.
    /// <para>
    /// This is <see cref="UpdateStatusAsync"/> behind the same atomic guard, for the one case that
    /// needs it: taking the platform's last working super administrator out of ACTIVE - by anyone,
    /// themselves included - has to be refused, and refusing it in application code loses the race
    /// against a second request doing the same thing. Every status write on an ordinary account
    /// stays on the plain path.
    /// </para>
    /// </summary>
    Task<bool> SetStatusIfAnotherActiveSuperAdminExistsAsync(
        int id,
        string status,
        string actor,
        CancellationToken cancellationToken);
}

/// <summary>One tenant, named the way a membership row names it.</summary>
/// <param name="TenantType"><c>company</c> or <c>supplier</c>.</param>
/// <param name="TenantCode">The tenant's own code. Never <c>"*"</c> - a whole dimension belongs in
/// <see cref="UserVisibilityFilter.WholeDimensions"/>, and a literal star here would match a real
/// row rather than a dimension.</param>
public sealed record TenantRef(string TenantType, string TenantCode);

/// <summary>
/// Which accounts a caller may see. Constructed by the caller's authority resolver, never by
/// anything the client can influence.
/// <para>
/// <b>Absent (null) and empty are different answers.</b> Null means unrestricted, which only the
/// platform super administrator gets. An instance with both lists empty means "administers
/// nothing" and matches no account at all. Defaulting a missing filter to an empty instance is
/// safe; defaulting it to null hands the caller the whole platform.
/// </para>
/// </summary>
/// <param name="WholeDimensions">Dimensions - <c>company</c>, <c>supplier</c> - the caller
/// administers in full.</param>
/// <param name="Tenants">Individual tenants the caller administers.</param>
public sealed record UserVisibilityFilter(
    IReadOnlyList<string> WholeDimensions,
    IReadOnlyList<TenantRef> Tenants)
{
    /// <summary>Matches nobody. The right stand-in for "this caller administers nothing".</summary>
    public static UserVisibilityFilter Nothing { get; } = new([], []);

    /// <summary>True when the filter names neither a dimension nor a tenant, and therefore selects
    /// no account. Worth asking before querying: the answer is knowable without a round trip.</summary>
    public bool MatchesNothing => WholeDimensions.Count == 0 && Tenants.Count == 0;
}

/// <summary>
/// The directory's query parameters, as bound from the request. It carries no visibility field on
/// purpose - see <see cref="IBackendUserRepository.ListAsync"/>.
/// </summary>
/// <param name="Page">1-based. Values below 1 are corrected by the caller before it gets here.</param>
/// <param name="PageSize">Row cap for one page.</param>
/// <param name="Status">Exact account status to filter on, or null for every status.</param>
/// <param name="Search">
/// A name fragment or a full email address. An address matches exactly and only exactly: addresses
/// are stored as a deterministic hash rather than as text, so there is nothing to match a prefix
/// against - which also means a name search can never accidentally reveal one.
/// </param>
public sealed record BackOfficeUserQuery(int Page, int PageSize, string? Status, string? Search);

/// <summary>One page of accounts plus the total the filter matched, which is what a pager needs and
/// what a second count query would otherwise cost.</summary>
public sealed record BackOfficeUserPage(IReadOnlyList<BackendUser> Users, int Total);

/// <summary>
/// A people-picker row: the four columns a display name can be composed from, and nothing else.
/// Deliberately not a <see cref="BackendUser"/> - the picker is unauthenticated by permission and
/// must not be able to return a status, a staff code or an address it was never asked for.
/// </summary>
public sealed record BackOfficeUserOption(int Id, string? FirstName, string? LastName, string? Nickname);

/// <summary>An account's current token version, for the cache that answers "is this token still
/// current" without a database round trip per request.</summary>
public sealed record BackendUserTokenVersion(int UserId, int TokenVersion);
