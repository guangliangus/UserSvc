using UserSvc.Domain.Abstractions;

namespace UserSvc.Domain.Auth;

/// <summary>Which of the two independently numbered account tables a session's subject id points into.</summary>
public static class SessionRealms
{
    /// <summary>An <c>identity.users</c> id — a consumer account.</summary>
    public const string Consumer = "CONSUMER";

    /// <summary>An <c>iam.backend_users</c> id — a back-office account.</summary>
    public const string BackOffice = "BACKOFFICE";

    /// <summary>Whether the value is one this service knows how to scope a query by.</summary>
    public static bool IsKnown(string realm) => realm is Consumer or BackOffice;
}

/// <summary>
/// Who a session belongs to: the <b>realm and the id together</b>, because neither half identifies
/// anybody on its own.
/// <para>
/// <c>identity.user_sessions.user_id</c> holds an id from one of two tables that number their rows
/// independently, so consumer 100 and back-office 100 are two different people wearing the same
/// integer. Passing that integer around by itself is what made "this user's active sessions" a
/// query spanning two realms: it put an operator's session in a consumer's device list, let a
/// consumer's device-limit eviction revoke an operator's session, and — through the partial unique
/// index on (user_id, device_id) — let one of the two lock the other out of a device entirely.
/// </para>
/// <para>
/// The type exists so that cannot be expressed. There is no public constructor and no way to reach
/// one without naming a realm, so a call site cannot forget the realm the way it could forget an
/// argument with a default. Every repository read and write of a subject's sessions takes one of
/// these rather than an <see cref="int"/>.
/// </para>
/// </summary>
public sealed record SessionSubject
{
    private SessionSubject(string realm, int userId)
    {
        Realm = realm;
        UserId = userId;
    }

    /// <summary>One of <see cref="SessionRealms"/>.</summary>
    public string Realm { get; }

    /// <summary>The subject id <b>within</b> <see cref="Realm"/>. Meaningless without it.</summary>
    public int UserId { get; }

    /// <summary>A consumer account: an <c>identity.users</c> id.</summary>
    public static SessionSubject Consumer(int userId) => For(SessionRealms.Consumer, userId);

    /// <summary>A back-office account: an <c>iam.backend_users</c> id.</summary>
    public static SessionSubject BackOffice(int userId) => For(SessionRealms.BackOffice, userId);

    /// <summary>
    /// A subject in the named realm. Used where the realm is data rather than a compile-time fact —
    /// reading a persisted session row, or deriving the realm of the caller behind a request.
    /// </summary>
    /// <exception cref="DomainRuleException">The realm is not one of <see cref="SessionRealms"/>, or
    /// the id is not a real id. Refused rather than defaulted: a subject that fell back to a realm
    /// would scope a revocation sweep to the wrong plane, and would do it silently.</exception>
    public static SessionSubject For(string realm, int userId)
    {
        if (!SessionRealms.IsKnown(realm))
        {
            throw new DomainRuleException(
                "SESSION_REALM_REQUIRED",
                $"'{realm}' is not a session realm. A session subject must state whether its id is a "
                + $"consumer ({SessionRealms.Consumer}) or a back-office ({SessionRealms.BackOffice}) account.");
        }

        if (userId <= 0)
        {
            throw new DomainRuleException(
                "SESSION_SUBJECT_REQUIRED",
                "A session subject id must be a real account id.");
        }

        return new SessionSubject(realm, userId);
    }

    /// <summary>Both halves, for a log line.</summary>
    public override string ToString() => $"{Realm}:{UserId}";
}
