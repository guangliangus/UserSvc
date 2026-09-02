using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Domain.Users;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// An in-memory stand-in for the two repositories and the unit of work, written by hand rather
/// than substituted.
/// <para>
/// <b>The reason it is not NSubstitute is that the behaviour under test is relational.</b> Almost
/// every case in this slice is "which row does this credential resolve to, and what row does that
/// leave behind" - a new identity riding on <c>User.Identities</c> until the save, a partial unique
/// index refusing a second active row, a read that must not see an insert until it is committed.
/// Stubbing each call individually would let the test assert its own arrangement back at itself,
/// which is exactly the failure mode that lets an ordering bug through.
/// </para>
/// <para>
/// It reproduces four EF behaviours the application service depends on, and nothing else:
/// </para>
/// <list type="number">
/// <item>An identity added to a tracked user's collection is inserted with that user's key on the
/// next save, and is invisible to queries until then.</item>
/// <item>A new user's key is assigned by the insert, so anything reading it earlier sees zero.</item>
/// <item>The two partial unique indexes refuse a second ACTIVE row and surface as
/// <see cref="ConflictException"/> with <c>CONFLICT</c> - the shape <c>UnitOfWork</c> produces from
/// SQLSTATE 23505.</item>
/// <item>The transaction body is replayable, because the real execution strategy replays it on a
/// transient failure. <see cref="ReplayTransactionOnce"/> turns that on so the guards against
/// double-inserting can actually be tested.</item>
/// </list>
/// </summary>
internal sealed class SocialTestStore : IUserRepository, IUserIdentityRepository, IUnitOfWork
{
    private readonly List<User> _users = [];
    private readonly List<UserIdentity> _identities = [];
    private readonly List<User> _pending = [];

    private int _nextUserId = 7000;
    private int _nextIdentityId = 1;

    /// <summary>How many times the application service committed. A cheap way to notice an extra save.</summary>
    public int SaveCount { get; private set; }

    /// <summary>Identities handed to <see cref="Update"/>, in order, for the backfill and self-heal cases.</summary>
    public List<UserIdentity> Updated { get; } = [];

    /// <summary>
    /// Replays every transaction body exactly once before letting it commit, the way the
    /// PostgreSQL execution strategy does after a transient failure. A service that adds an entity
    /// inside the body without a guard inserts it twice under this.
    /// </summary>
    public bool ReplayTransactionOnce { get; set; }

    /// <summary>
    /// Runs just before the next save and can plant a row - the way a concurrent request would -
    /// so the insert that follows hits the unique index for real instead of against a mocked
    /// exception.
    /// </summary>
    public Action? BeforeNextSave { get; set; }

    /// <summary>
    /// Makes the next save fail with an exception that is <b>not</b> an
    /// <see cref="AppException"/> - the shape a check-constraint violation, a foreign key or a
    /// dropped connection actually has, because <c>UnitOfWork</c> only translates the concurrency
    /// token and SQLSTATE 23505. It exists so the best-effort writes can be shown to survive one.
    /// </summary>
    public Exception? FailNextSaveWith { get; set; }

    public IReadOnlyList<User> Users => _users;

    public IReadOnlyList<UserIdentity> Identities => _identities;

    // ------------------------------------------------------------------ seeding

    public User GivenUser(
        string status = UserStatuses.Active,
        string passwordHash = "",
        int? id = null)
    {
        var user = new User
        {
            Id = id ?? _nextUserId++,
            Status = status,
            PasswordHash = passwordHash,
            Nickname = "seeded",
            CreatedAt = DateTimeOffset.UnixEpoch,
            UpdatedAt = DateTimeOffset.UnixEpoch,
        };

        _users.Add(user);

        return user;
    }

    public UserIdentity GivenIdentity(
        int userId,
        string identityType,
        string identifierHash,
        string provider = "",
        string providerUid = "",
        string providerDetails = "{}",
        string status = UserStatuses.Active,
        string ciphertext = "")
    {
        var identity = new UserIdentity
        {
            Id = _nextIdentityId++,
            UserId = userId,
            IdentityType = identityType,
            IdentifierHash = identifierHash,
            IdentifierCiphertext = ciphertext,
            Provider = provider,
            ProviderUid = providerUid,
            ProviderDetails = providerDetails,
            Status = status,
            CreatedAt = DateTimeOffset.UnixEpoch,
            UpdatedAt = DateTimeOffset.UnixEpoch,
        };

        _identities.Add(identity);

        return identity;
    }

    // ------------------------------------------------------------------ IUserRepository

    public Task<User?> FindByIdAsync(int userId, CancellationToken cancellationToken) =>
        Task.FromResult(_users.Find(u => u.Id == userId));

    public Task<User?> FindByIdentifierHashAsync(string identifierHash, CancellationToken cancellationToken)
    {
        var identity = _identities.Find(i =>
            i.IdentifierHash == identifierHash && i.Status == UserStatuses.Active);

        return Task.FromResult(identity is null ? null : _users.Find(u => u.Id == identity.UserId));
    }

    /// <summary>
    /// Idempotent, like EF's own <c>Add</c> on an entity it is already tracking - which is what
    /// makes a replayed transaction body safe rather than a source of duplicate rows.
    /// </summary>
    public void Add(User user)
    {
        if (!_pending.Contains(user) && !_users.Contains(user))
        {
            _pending.Add(user);
        }
    }

    // ------------------------------------------------------------------ IUserIdentityRepository

    public Task<UserIdentity?> FindActiveAsync(
        string identityType,
        string identifierHash,
        CancellationToken cancellationToken)
    {
        Reads.Add((identityType, identifierHash));

        return Task.FromResult(_identities.Find(i =>
            i.IdentityType == identityType
            && i.IdentifierHash == identifierHash
            && i.Status == UserStatuses.Active));
    }

    public Task<UserIdentity?> FindActiveByIdentifierAndProviderAsync(
        string identityType,
        string identifierHash,
        string provider,
        CancellationToken cancellationToken)
    {
        Reads.Add((identityType, identifierHash));

        return Task.FromResult(_identities.Find(i =>
            i.IdentityType == identityType
            && i.IdentifierHash == identifierHash
            && i.Provider == provider
            && i.Status == UserStatuses.Active));
    }

    public Task<UserIdentity?> FindActiveByProviderAsync(
        string identityType,
        string provider,
        string providerUid,
        CancellationToken cancellationToken) =>
        Task.FromResult(_identities.Find(i =>
            i.IdentityType == identityType
            && i.Provider == provider
            && i.ProviderUid == providerUid
            && i.Status == UserStatuses.Active));

    public Task<UserIdentity?> FindEarliestActiveWechatByUnionIdAsync(
        string unionId,
        CancellationToken cancellationToken) =>
        Task.FromResult(_identities
            .Where(i => i.IdentityType is IdentityTypes.Wechat or IdentityTypes.WechatMini
                        && i.ProviderUid == unionId
                        && i.Status == UserStatuses.Active)
            .OrderBy(i => i.Id)
            .FirstOrDefault());

    public Task<IReadOnlyList<UserIdentity>> ListActiveByUserAsync(
        int userId,
        CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<UserIdentity>>(
            [.. _identities.Where(i => i.UserId == userId && i.Status == UserStatuses.Active).OrderBy(i => i.Id)]);

    public void Update(UserIdentity identity) => Updated.Add(identity);

    /// <summary>Every blind-index lookup, so a test can assert that a fast path skipped one.</summary>
    public List<(string IdentityType, string IdentifierHash)> Reads { get; } = [];

    // ------------------------------------------------------------------ IUnitOfWork

    public Task<int> SaveChangesAsync(CancellationToken cancellationToken)
    {
        var hook = BeforeNextSave;
        BeforeNextSave = null;
        hook?.Invoke();

        var failure = FailNextSaveWith;
        FailNextSaveWith = null;

        if (failure is not null)
        {
            throw failure;
        }

        SaveCount++;

        foreach (var user in _pending)
        {
            if (user.Id == 0)
            {
                user.Id = _nextUserId++;
            }

            _users.Add(user);
        }

        _pending.Clear();

        var written = 0;

        foreach (var user in _users)
        {
            foreach (var identity in user.Identities)
            {
                if (identity.Id != 0)
                {
                    continue;
                }

                RequireUnique(identity);

                identity.Id = _nextIdentityId++;
                identity.UserId = user.Id;
                _identities.Add(identity);
                written++;
            }
        }

        return Task.FromResult(written);
    }

    public async Task ExecuteInTransactionAsync(
        Func<CancellationToken, Task> action,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);

        if (ReplayTransactionOnce)
        {
            ReplayTransactionOnce = false;
            await action(cancellationToken);
        }

        await action(cancellationToken);
    }

    /// <summary>
    /// The two partial unique indexes from <c>db/0001_identity.sql</c> plus this slice's addition,
    /// as the application service will meet them: a <see cref="ConflictException"/> carrying
    /// <c>CONFLICT</c>, which is what <c>UnitOfWork</c> turns SQLSTATE 23505 into.
    /// </summary>
    private void RequireUnique(UserIdentity candidate)
    {
        if (candidate.Status != UserStatuses.Active)
        {
            return;
        }

        var duplicateIdentifier = _identities.Exists(i =>
            i.Status == UserStatuses.Active
            && i.IdentityType == candidate.IdentityType
            && i.IdentifierHash == candidate.IdentifierHash);

        var duplicateProviderKey = candidate.ProviderUid.Length > 0 && _identities.Exists(i =>
            i.Status == UserStatuses.Active
            && i.IdentityType == candidate.IdentityType
            && i.Provider == candidate.Provider
            && i.ProviderUid == candidate.ProviderUid);

        if (duplicateIdentifier || duplicateProviderKey)
        {
            throw new ConflictException(
                ErrorCodes.Conflict, "The value violates the uniqueness constraint 'test'.");
        }
    }
}
