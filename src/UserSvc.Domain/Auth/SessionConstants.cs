namespace UserSvc.Domain.Auth;

/// <summary>Login session states.</summary>
public static class SessionStatuses
{
    public const string Active = "ACTIVE";
    public const string Revoked = "REVOKED";
}

/// <summary>Why a session was revoked. Surfaces in the "signed-in devices" screen and in audit.</summary>
public static class RevocationReasons
{
    /// <summary>The user signed out on this device.</summary>
    public const string Self = "SELF";
    /// <summary>The user kicked this device from another one.</summary>
    public const string OtherDevice = "OTHER_DEVICE";
    /// <summary>The same device signed in again and the old session stepped aside.</summary>
    public const string Superseded = "SUPERSEDED";
    /// <summary>The account hit its active-device cap and the least recently used session gave way.</summary>
    public const string DeviceLimit = "DEVICE_LIMIT";
    /// <summary>A password change signed every device out.</summary>
    public const string PasswordChange = "PASSWORD_CHANGE";
    /// <summary>An administrator forced the device offline.</summary>
    public const string Admin = "ADMIN";
    /// <summary>A rotated refresh token was presented again — treated as a leak.</summary>
    public const string TokenReplay = "TOKEN_REPLAY";
    /// <summary>The account was closed by its owner. Distinct from SELF and ADMIN on purpose: the
    /// session did not end, the account it belonged to stopped existing.</summary>
    public const string Deregistered = "DEREGISTERED";
}
