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
    public const string AlreadyRegistered = "ALREADY_REGISTERED";

    // --- Sessions and tokens ---
    public const string SessionNotFound = "SESSION_NOT_FOUND";
    public const string InvalidToken = "INVALID_TOKEN";
    public const string ExpiredToken = "EXPIRED_TOKEN";
    public const string RefreshTokenReplayed = "REFRESH_TOKEN_REPLAYED";
    public const string SessionRevoked = "SESSION_REVOKED";

    // --- Verification codes and risk control ---
    public const string Unregistered = "UNREGISTERED";
    public const string InvalidPhoneFormat = "INVALID_PHONE_FORMAT";
    public const string InvalidEmailFormat = "INVALID_EMAIL_FORMAT";
    public const string VerificationCodeIncorrect = "VERIFICATION_CODE_INCORRECT";
    public const string VerificationCodeExpired = "VERIFICATION_CODE_EXPIRED";
    public const string VerificationFailed = "VERIFICATION_FAILED";
    public const string SendFailed = "SEND_FAILED";
    public const string CaptchaRequired = "CAPTCHA_REQUIRED";
    public const string CaptchaInvalid = "CAPTCHA_INVALID";
    public const string RiskControlCooldown = "RISK_CONTROL_COOLDOWN";
    public const string NotImplemented = "NOT_IMPLEMENTED";
}
