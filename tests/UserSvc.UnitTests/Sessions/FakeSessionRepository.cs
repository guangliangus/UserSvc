using UserSvc.Application.Ports.Auth;
using UserSvc.Domain.Auth;

namespace UserSvc.UnitTests.Sessions;

/// <summary>
/// An in-memory <see cref="IUserSessionRepository"/> that filters the way the real one does.
/// <para>
/// It is a hand-written fake rather than a substitute because the thing under test is a
/// <b>predicate</b>: a substitute told to return a fixed list would pass whatever subject the
/// service handed it, which is exactly the mistake being guarded against. Here the rows carry their
/// own realm and the reads honour it, so passing the wrong subject returns the wrong rows and the
/// test fails.
/// </para>
/// </summary>
internal sealed class FakeSessionRepository : IUserSessionRepository
{
    private readonly List<UserSession> _rows = [];

    /// <summary>Every row ever staged, in insert order.</summary>
    public IReadOnlyList<UserSession> Rows => _rows;

    /// <summary>How many times a subject-scoped read has been served.</summary>
    public int SubjectReads { get; private set; }

    /// <summary>Seed a row that already exists, as a sign-in would have left it.</summary>
    public UserSession Seed(UserSession session)
    {
        _rows.Add(session);
        return session;
    }

    public Task<UserSession?> FindBySessionIdAsync(string sessionId, CancellationToken cancellationToken) =>
        Task.FromResult(_rows.Find(s => s.SessionId == sessionId));

    public Task<IReadOnlyList<UserSession>> ListActiveBySubjectAsync(
        SessionSubject subject,
        CancellationToken cancellationToken)
    {
        SubjectReads++;

        // The realm half is the whole point: drop it and this fake reproduces the defect.
        IReadOnlyList<UserSession> active =
            [.. _rows.Where(s => s.IsActive && s.BelongsTo(subject))];

        return Task.FromResult(active);
    }

    public void Add(UserSession session) => _rows.Add(session);
}
