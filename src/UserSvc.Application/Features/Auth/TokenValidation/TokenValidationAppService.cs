using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Ports.Auth;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.Auth.TokenValidation;

/// <summary>
/// Answers the two questions a relying service cannot answer for itself about one of this service's
/// access tokens: <b>is the session behind it still alive</b>, and <b>what does its holder
/// currently hold</b>.
/// <para>
/// Signature, issuer, audience and expiry are deliberately <b>not</b> among them. Those are settled
/// by the caller's own JWKS validation before this service is ever asked, and re-checking them here
/// would be a second implementation of a check that already has one. See
/// <c>AuthValidationController</c> for the full reasoning about what survived the port and what did
/// not.
/// </para>
/// <para>
/// <b>It reads the pipeline's own answers rather than recomputing them.</b> The authority face
/// comes from <see cref="IBackOfficeCaller"/>, which is what the permission gates read, so this
/// endpoint and those gates cannot disagree — and they would, given two code paths and a five
/// minute snapshot cache.
/// </para>
/// </summary>
public sealed class TokenValidationAppService(
    IBackOfficeCaller caller,
    IUserSessionRepository sessions,
    IClock clock,
    ILogger<TokenValidationAppService> logger)
{
    public async Task<TokenValidationResponse> DescribeAsync(
        ValidatedTokenFacts token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (token.AwaitingTenantContext)
        {
            // A pre-tenant token proves authentication and carries no authorization context at all.
            // A relying service must never accept one for business traffic, and the honest answer is
            // not "here is an empty authority" - that reads as "this person holds nothing", when in
            // fact nobody has asked them yet which company they are acting for.
            throw new UnauthorizedException(
                ErrorCodes.TenantContextRequired,
                "This session has not chosen a company or supplier to act as. Select a context and exchange the token before using it.");
        }

        var userId = caller.UserId;

        if (userId <= 0)
        {
            // Unreachable behind the endpoint's authorization requirement. Kept because a caller
            // of zero is a real value everywhere in this codebase and means "no caller" - reporting
            // an authority face for it would be reporting somebody else's.
            throw new UnauthorizedException(ErrorCodes.Unauthorized, "Authentication is required.");
        }

        var session = await FindLiveSessionAsync(token.SessionId, userId, cancellationToken);
        var internalCaller = token.IsInternal;

        return new TokenValidationResponse
        {
            UserId = userId,
            SessionId = token.SessionId,
            IsInternal = internalCaller,
            ExpiresIn = SecondsUntil(token.ExpiresAt),
            IssuedAt = token.IssuedAt,
            ExpiresAt = token.ExpiresAt,
            Platform = session?.Platform ?? string.Empty,
            DeviceId = session?.DeviceId ?? string.Empty,
            IsTenantAdmin = internalCaller && token.IsTenantAdmin,
            ActiveTenant = internalCaller ? ActiveTenant() : null,

            // Consumer tokens leave all four null: the consumer plane has no roles, permissions,
            // menus or data scopes, and an empty list would tell a relying service that this person
            // was granted nothing - a different and wrong statement.
            Roles = internalCaller ? caller.Authz.Roles : null,
            Permissions = internalCaller ? caller.Authz.Permissions : null,
            Menus = internalCaller ? caller.Authz.Menus : null,
            Scopes = internalCaller ? DeclareBothDimensions(caller.Authz.Scopes) : null,
        };
    }

    /// <summary>
    /// The authoritative liveness check, and the one thing local JWKS validation cannot do.
    /// <para>
    /// <b>Why the database and not just the revocation set.</b> The per-request
    /// <c>RevokedSessionMiddleware</c> reads Redis and <b>fails open</b> on purpose: it is an extra
    /// check laid over a fully validated token, and the ten-minute token lifetime is its backstop.
    /// That trade does not transfer here, because for this endpoint the liveness answer <i>is</i> the
    /// product - answering it fail-open would make the whole call pointless. So the session row is
    /// consulted, which is the same source the refresh path treats as authoritative.
    /// </para>
    /// <para>
    /// <b>A row that belongs to a different account is a refusal</b>, and a row that is not there
    /// is not. Only consumer device logins write
    /// <c>user_sessions</c>; a back-office credential has a <c>sid</c> with no row behind it yet.
    /// Refusing on absence would take the entire back office down over a table it does not populate,
    /// which is the failure mode this repository has had three times. Absence is logged and passed
    /// over; a row that exists and is revoked is refused.
    /// </para>
    /// </summary>
    private async Task<UserSession?> FindLiveSessionAsync(
        string sessionId, int userId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(sessionId))
        {
            return null;
        }

        var session = await sessions.FindBySessionIdAsync(sessionId, cancellationToken);

        if (session is null)
        {
            logger.LogDebug(
                "Token validation found no session row for {SessionId}; reporting liveness from the token alone.",
                sessionId);

            return null;
        }

        if (session.UserId != userId)
        {
            // The row exists but belongs to somebody else, so nothing about it may be reported and
            // it certainly must not answer this token's liveness question. Reachable only through a
            // bug or a forged claim - session ids are v7 GUIDs - which is exactly why it is refused
            // rather than passed over: passing over it would answer with the device fields of an
            // account the caller is not, and would take the liveness verdict from that account's
            // session.
            logger.LogWarning(
                "Session {SessionId} belongs to account {Owner}, not to the presenting account "
                + "{Caller}; refusing to describe the token.",
                sessionId,
                session.UserId,
                userId);

            throw new UnauthorizedException(
                ErrorCodes.InvalidToken, "This credential is not valid. Sign in again.");
        }

        if (!session.IsActive)
        {
            throw new UnauthorizedException(
                ErrorCodes.SessionRevoked,
                "This session has been signed out. Sign in again.");
        }

        return session;
    }

    /// <summary>
    /// Where the caller is acting, in the same shape the back-office shell reads.
    /// <para>
    /// A supplier context also reports the company its supplier is mounted on, and that mount is
    /// only knowable from the data-scope envelope - the act claim carries the supplier code and
    /// nothing else.
    /// </para>
    /// </summary>
    private ActiveTenantResponse? ActiveTenant()
    {
        var actType = caller.ActType;

        // Deliberately not Tenancy.ActTypes.IsKnown: there are two ActTypes classes in the domain
        // (Iam and Tenancy) with the same four constants, and importing both here would be
        // ambiguous. See the follow-ups - they should be one type.
        if (actType is not (ActTypes.Platform or ActTypes.Global or ActTypes.Company or ActTypes.Supplier))
        {
            return null;
        }

        var company = actType == ActTypes.Company ? caller.ActCode : string.Empty;
        var supplier = actType == ActTypes.Supplier ? caller.ActCode : string.Empty;

        if (actType == ActTypes.Supplier)
        {
            var mounted = caller.Authz.ScopeFor(TenantTypes.Company).Values;

            if (mounted.Count > 0 && mounted[0].Length > 0)
            {
                company = mounted[0];
            }
        }

        return new ActiveTenantResponse
        {
            Type = actType.ToLowerInvariant(),
            CompanyCode = company,
            SupplierCode = supplier,
            Dimension = caller.ActDim,
        };
    }

    /// <summary>
    /// Both dimensions, always, in a fixed order.
    /// <para>
    /// <see cref="EffectiveAuthz.Empty"/> carries an empty dictionary, and an <b>absent</b>
    /// dimension is read downstream as "unrestricted" - so shipping it as-is would turn a caller
    /// who holds nothing into a caller who may read everything. Declaring both dimensions with an
    /// empty claim is how "none" is said out loud.
    /// </para>
    /// </summary>
    private static IReadOnlyDictionary<string, ScopeClaim> DeclareBothDimensions(
        IReadOnlyDictionary<string, ScopeClaim> scopes)
    {
        var envelope = new Dictionary<string, ScopeClaim>(StringComparer.Ordinal);

        foreach (var dimension in TenantTypes.All)
        {
            envelope[dimension] = scopes.TryGetValue(dimension, out var claim) ? claim : ScopeClaim.Empty;
        }

        return envelope;
    }

    private long SecondsUntil(DateTimeOffset? expiresAt)
    {
        if (expiresAt is not { } deadline)
        {
            return 0;
        }

        var remaining = (deadline - clock.UtcNow).TotalSeconds;

        return remaining <= 0 ? 0 : (long)remaining;
    }
}
