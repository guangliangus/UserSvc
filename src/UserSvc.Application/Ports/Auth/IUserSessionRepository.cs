using UserSvc.Domain.Auth;

namespace UserSvc.Application.Ports.Auth;

/// <summary>
/// Persistence outlet for login sessions.
/// <para>
/// <b>Every read of "a subject's sessions" takes a <see cref="SessionSubject"/>, never a bare id.</b>
/// The table's <c>user_id</c> holds an id from either of two independently numbered account tables,
/// so a method that accepted an <see cref="int"/> would be asking a question with two answers — and
/// the shape of the bug it produced was not a wrong number but a consumer's device-limit eviction
/// revoking an operator's session. The signature is the enforcement.
/// </para>
/// </summary>
public interface IUserSessionRepository
{
    /// <summary>
    /// Find a session by its <c>sid</c>.
    /// <para>
    /// <b>Deliberately realm-free</b>, and the one read here that is. A <c>sid</c> is a
    /// server-generated GUID drawn from a single sequence for both planes and carries a unique
    /// index across the whole table, so it resolves to exactly one row on its own. The refresh and
    /// replay paths hold nothing but the <c>sid</c>, so requiring a realm here would mean deriving
    /// one from the token to feed a lookup that does not need it — and a wrongly derived realm
    /// would then turn a live session into "no such session".
    /// </para>
    /// </summary>
    Task<UserSession?> FindBySessionIdAsync(string sessionId, CancellationToken cancellationToken);

    /// <summary>
    /// Every active session of one subject, within that subject's realm only. Backs the
    /// signed-in-devices screen, the device-limit eviction and the sign-out-everywhere sweep — the
    /// three places that used to cross the two planes.
    /// </summary>
    Task<IReadOnlyList<UserSession>> ListActiveBySubjectAsync(
        SessionSubject subject,
        CancellationToken cancellationToken);

    /// <summary>Stage a new session for insert. The session already carries its own realm.</summary>
    void Add(UserSession session);
}
