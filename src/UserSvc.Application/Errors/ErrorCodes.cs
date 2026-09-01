namespace UserSvc.Application.Errors;

/// <summary>
/// Machine-readable error codes. <b>Part of the client contract: add, never rename</b> — a rename
/// is a breaking change. They surface as the <c>errorCode</c> extension member on ProblemDetails
/// (decision 09).
/// </summary>
public static class ErrorCodes
{
    // --- General ---
    public const string BadRequest = "BAD_REQUEST";
    public const string ValidationFailed = "VALIDATION_FAILED";
    public const string Unauthorized = "UNAUTHORIZED";
    public const string Forbidden = "FORBIDDEN";
    public const string NotFound = "NOT_FOUND";
    public const string Conflict = "CONFLICT";
    public const string ConcurrencyConflict = "CONCURRENCY_CONFLICT";
    public const string RateLimitExceeded = "RATE_LIMIT_EXCEEDED";
    public const string UpstreamUnavailable = "UPSTREAM_SERVICE_UNAVAILABLE";
    public const string InternalError = "INTERNAL_ERROR";

    // --- Identity and profile ---
    public const string UserNotFound = "USER_NOT_FOUND";
    public const string AccountDisabled = "ACCOUNT_DISABLED";
    public const string IdentityAlreadyBound = "IDENTITY_ALREADY_BOUND";

    // --- Sessions and tokens ---
    public const string SessionNotFound = "SESSION_NOT_FOUND";
    public const string InvalidToken = "INVALID_TOKEN";
    public const string ExpiredToken = "EXPIRED_TOKEN";
    public const string RefreshTokenReplayed = "REFRESH_TOKEN_REPLAYED";
    public const string SessionRevoked = "SESSION_REVOKED";
}
