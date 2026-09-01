namespace UserSvc.Domain.Users;

/// <summary>Account lifecycle states.</summary>
public static class UserStatuses
{
    public const string Pending = "PENDING";
    public const string Active = "ACTIVE";
    public const string Disabled = "DISABLED";
    public const string Deleted = "DELETED";
}

/// <summary>Sources a login identity can come from.</summary>
public static class IdentityTypes
{
    public const string Phone = "PHONE";
    public const string Email = "EMAIL";
    public const string Wechat = "WECHAT";
    public const string WechatMini = "WECHAT_MINI";
    public const string Firebase = "FIREBASE";
    public const string Line = "LINE";
    public const string Passkey = "PASSKEY";
}
