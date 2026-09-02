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

    /// <summary>
    /// A capability whose configuration this deployment does not carry - a provider credential, a
    /// storage connection string. Distinct from <see cref="InternalError"/> so an operator reading
    /// the response knows to look at the secrets rather than at the code, and distinct from
    /// <see cref="NotImplemented"/> because the code exists and is only waiting for a value.
    /// </summary>
    public const string NotConfigured = "NOT_CONFIGURED";

    // --- Back-office accounts ---

    /// <summary>The address is not on the corporate domain allow-list. Back-office only.</summary>
    public const string InvalidDomain = "INVALID_DOMAIN";

    // --- Back-office platform ownership ---
    // Two statuses each, deliberately: 403 when the caller lacks the standing (nothing about the
    // request can be corrected), 409 when the target is the last active holder (a conflict with
    // current state, and the operator's fix is to appoint another one).

    public const string SuperAdminRequired = "SUPER_ADMIN_REQUIRED";
    public const string SuperAdminExclusive = "SUPER_ADMIN_EXCLUSIVE";

    // --- Back-office tenancy ---

    /// <summary>The caller's active context does not reach this tenant, or it has no active
    /// context at all.</summary>
    public const string TenantNotAuthorized = "TENANT_NOT_AUTHORIZED";

    /// <summary>The membership is suspended. Distinct from <see cref="TenantInactive"/> on purpose:
    /// this one is a decision somebody made about this person.</summary>
    public const string TenantDisabled = "TENANT_DISABLED";

    /// <summary>The tenant is switched off in the master data - a platform-side state that can be
    /// flipped back, which is why it revokes nothing.</summary>
    public const string TenantInactive = "TENANT_INACTIVE";

    /// <summary>Only an administrator of a tenant may manage its members.</summary>
    public const string CallerNotAdmin = "CALLER_NOT_ADMIN";

    public const string MemberNotFound = "MEMBER_NOT_FOUND";
    public const string MemberAlreadyExists = "MEMBER_ALREADY_EXISTS";

    /// <summary>The write would leave the tenant without an administrator, or one administrator
    /// tried to edit another. Both point at the explicit transfer flow.</summary>
    public const string AdminTransferRequired = "ADMIN_TRANSFER_REQUIRED";

    // --- Back-office roles, permissions and menus ---

    public const string RoleCodeExists = "ROLE_CODE_EXISTS";
    public const string RoleCodeReserved = "ROLE_CODE_RESERVED";
    public const string RoleCategoryInvalid = "ROLE_CATEGORY_INVALID";

    /// <summary>A role filed under a category that cannot be bound in this kind of tenant.</summary>
    public const string RoleCategoryMismatch = "ROLE_CATEGORY_MISMATCH";

    /// <summary>A role outside the caller's own delegation ceiling.</summary>
    public const string RoleNotDelegable = "ROLE_NOT_DELEGABLE";

    public const string RoleOwnerRequired = "ROLE_OWNER_REQUIRED";
    public const string RoleOwnerNotAllowed = "ROLE_OWNER_NOT_ALLOWED";
    public const string RoleParentInvalid = "ROLE_PARENT_INVALID";
    public const string RoleHasChildren = "ROLE_HAS_CHILDREN";
    public const string RoleInUse = "ROLE_IN_USE";
    public const string RoleNotGloballyAssignable = "ROLE_NOT_GLOBALLY_ASSIGNABLE";
    public const string RoleGrantsExceedParent = "ROLE_GRANTS_EXCEED_PARENT";
    public const string MenuNotGranted = "MENU_NOT_GRANTED";
    public const string MenuHasChildren = "MENU_HAS_CHILDREN";

    // --- Passkeys / WebAuthn ---
    public const string PasskeyFlowExpired = "PASSKEY_FLOW_EXPIRED";
    public const string PasskeyInvalidRequest = "PASSKEY_INVALID_REQUEST";
    public const string PasskeyVerificationFailed = "PASSKEY_VERIFICATION_FAILED";
    public const string PasskeyCredentialNotFound = "PASSKEY_CREDENTIAL_NOT_FOUND";
    public const string PasskeyNotFound = "PASSKEY_NOT_FOUND";
    public const string PasskeyAlreadyRegistered = "PASSKEY_ALREADY_REGISTERED";

    /// <summary>The authenticator reported a signature counter no higher than the one we stored,
    /// which is the one thing that cannot happen to a genuine credential. Refusing here is the
    /// security property passkeys buy over a password.</summary>
    public const string PasskeyPossibleClone = "PASSKEY_POSSIBLE_CLONE";

    /// <summary>Removing this credential would leave the account with no way to sign in.</summary>
    public const string PasskeyLastLoginMethod = "PASSKEY_LAST_LOGIN_METHOD";

    // --- Third-party identity providers ---
    public const string WechatLoginFailed = "WECHAT_LOGIN_FAILED";
    public const string LineLoginFailed = "LINE_LOGIN_FAILED";
    public const string InvalidState = "INVALID_STATE";
    public const string BindFailed = "BIND_FAILED";
    public const string BindingTokenInvalid = "BINDING_TOKEN_INVALID";
    public const string AccountNotActivated = "ACCOUNT_NOT_ACTIVATED";
    public const string FirebaseProviderRequired = "FIREBASE_PROVIDER_REQUIRED";
    public const string FirebaseProviderNotAllowed = "FIREBASE_PROVIDER_NOT_ALLOWED";
    public const string FirebaseProviderMismatch = "FIREBASE_PROVIDER_MISMATCH";
    public const string FirebaseIdentityAlreadyBound = "FIREBASE_IDENTITY_ALREADY_BOUND";
    public const string FirebaseIdTokenInvalid = "FIREBASE_ID_TOKEN_INVALID";
    public const string FirebaseIdTokenExpired = "FIREBASE_ID_TOKEN_EXPIRED";
    public const string FirebaseProjectMismatch = "FIREBASE_PROJECT_MISMATCH";
    public const string FirebaseConfigUnavailable = "FIREBASE_CONFIG_UNAVAILABLE";
    public const string FirebaseUserLookupFailed = "FIREBASE_USER_LOOKUP_FAILED";

    // --- Uploads ---
    /// <summary>413, not 400: the request was well formed and simply too big.</summary>
    public const string FileTooLarge = "FILE_TOO_LARGE";

    /// <summary>415, not 400: the bytes are not a media type this endpoint accepts. Decided from
    /// the magic bytes, never from the declared content type or the file name.</summary>
    public const string InvalidFileType = "INVALID_FILE_TYPE";

    public const string TooManyFiles = "TOO_MANY_FILES";
}
