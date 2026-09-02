namespace UserSvc.Domain.BackOffice;

/// <summary>
/// Back-office account lifecycle. Text in the database with a CHECK constraint, enumerated here -
/// the team convention keeps PostgreSQL enums out of the schema because adding a value to one is a
/// migration, while adding a value here is a deployment.
/// </summary>
public static class BackendUserStatuses
{
    /// <summary>Registered, not yet activated. <b>May sign in</b> - it is simply granted no
    /// authority, so onboarding can finish without anyone handing it access first.</summary>
    public const string Pending = "PENDING";

    public const string Active = "ACTIVE";

    /// <summary>Signed out of the product entirely, across every tenant. A verdict on the person,
    /// unlike suspending one membership.</summary>
    public const string Disabled = "DISABLED";

    public static bool IsKnown(string? status) => status is Pending or Active or Disabled;
}

/// <summary>Where a back-office account came from, which decides whether the corporate
/// email-domain gate applies to it.</summary>
public static class BackendUserOrigins
{
    /// <summary>Group staff. Subject to the corporate domain allow-list at sign-in.</summary>
    public const string Internal = "INTERNAL";

    /// <summary>An external B2B user - a supplier or an agency - who authenticates with whatever
    /// mailbox they have.</summary>
    public const string External = "EXTERNAL";

    public static bool IsKnown(string? origin) => origin is Internal or External;
}

/// <summary>
/// The kinds of back-office login identity. <b>The casing is load-bearing</b>: the live CHECK
/// constraint and the partial unique indexes match these literals exactly, so <c>"otp"</c> would
/// be refused by the database and <c>"EMAIL"</c> would silently create a second identity space.
/// </summary>
public static class BackendIdentityTypes
{
    public const string Email = "email";

    public const string Phone = "phone";

    /// <summary>The corporate employee number, authenticated by the staff directory's one-time
    /// password. Uppercase, unlike the other two.</summary>
    public const string Otp = "OTP";

    public static bool IsKnown(string? identityType) => identityType is Email or Phone or Otp;
}

/// <summary>Identity lifecycle. Only ACTIVE rows participate in the unique indexes, which is what
/// makes an identity revocable and its address later reclaimable.</summary>
public static class BackendIdentityStatuses
{
    public const string Active = "ACTIVE";

    public const string Disabled = "DISABLED";
}
