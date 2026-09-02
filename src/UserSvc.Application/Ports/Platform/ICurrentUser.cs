using UserSvc.Domain.Auth;

namespace UserSvc.Application.Ports.Platform;

/// <summary>
/// The caller behind the current request, populated by the API layer from validated token claims.
/// The application layer knows nothing about HTTP or JWT — only who is calling.
/// </summary>
public interface ICurrentUser
{
    /// <summary>The token's <c>sub</c>. Null when unauthenticated.</summary>
    int? UserId { get; }

    /// <summary>The token's <c>sid</c> — the server-generated session id, and the only
    /// trustworthy basis for signing a device out (decision 11).</summary>
    string? SessionId { get; }

    /// <summary>
    /// Which of the two independently numbered account tables <see cref="UserId"/> points into, as
    /// one of <see cref="SessionRealms"/>.
    /// <para>
    /// <b><c>sub</c> on its own does not identify anybody.</b> A back-office access token and a
    /// consumer access token are issued by the same authority, carry the same claim names and are
    /// both accepted by a bare <c>[Authorize]</c>; their <c>sub</c> values come from
    /// <c>iam.backend_users</c> and <c>identity.users</c>, which number their rows independently.
    /// So back-office operator 5 and consumer 5 are two different people wearing the same integer,
    /// and any endpoint that reads <c>sub</c> alone is one collision away from acting on the wrong
    /// person's data.
    /// </para>
    /// <para>
    /// The value is derived from the token's <b>granted scopes</b> - the same positive signal the
    /// back-office authorization policies and <c>ValidatedTokenFacts.IsInternal</c> are built on -
    /// and never from the shape or size of the subject id. Deriving it from the absence of
    /// something would fail open, which is the mistake <c>BackOfficeAuthorization</c> records.
    /// </para>
    /// </summary>
    string Realm { get; }

    /// <summary>The token's <c>sub</c>, or a 401 when there is no caller.</summary>
    int RequireUserId();

    /// <summary>
    /// The caller as a session subject: <see cref="Realm"/> and <see cref="UserId"/> together,
    /// which is the only form in which either half means anything.
    /// <para>
    /// A default implementation rather than a member every adapter restates, so the two halves
    /// cannot be paired up differently in two places.
    /// </para>
    /// </summary>
    /// <exception cref="UserSvc.Domain.Abstractions.DomainRuleException">The realm is not one this
    /// service knows how to scope a query by. Refused rather than defaulted - a fallback realm
    /// would point a revocation at the wrong plane, silently.</exception>
    SessionSubject RequireSubject() => SessionSubject.For(Realm, RequireUserId());

    /// <summary>
    /// The caller's <c>identity.users</c> id, for an endpoint that only makes sense for a consumer.
    /// <para>
    /// <b>Every consumer-plane endpoint has to ask for the id this way, because a bare
    /// <c>[Authorize]</c> does not keep a back-office token out.</b> Both planes are served by one
    /// OpenIddict instance, so an operator's access token is a perfectly valid bearer token here,
    /// and its <c>sub</c> is an <c>iam.backend_users</c> id that these endpoints then look up in
    /// <c>identity.users</c>. Measured against a running host before this existed: a back-office
    /// token with <c>sub=1</c> read consumer 1's profile at 200, and <c>DELETE /account</c> with
    /// the same token would have closed that consumer's account and signed every one of their
    /// devices out. Nothing in either request was malformed - the two planes simply number their
    /// accounts independently, which is the same collision <see cref="SessionSubject"/> exists to
    /// prevent one layer down.
    /// </para>
    /// <para>
    /// 403 rather than 401: the caller is authenticated and there is nothing about the request to
    /// correct, which is what 403 means in this service's status grouping. It is also not an
    /// existence oracle - the answer depends only on the presented token's own scopes, never on
    /// whether the id names anybody.
    /// </para>
    /// </summary>
    /// <exception cref="Errors.ForbiddenException">The caller is not a consumer.</exception>
    int RequireConsumerId()
    {
        var userId = RequireUserId();

        return Realm == SessionRealms.Consumer
            ? userId
            : throw new Errors.ForbiddenException(
                Errors.ErrorCodes.Forbidden,
                "This endpoint serves consumer accounts. A back-office credential cannot act on one.");
    }
}
