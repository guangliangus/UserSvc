namespace UserSvc.Domain.Verification;

/// <summary>
/// What a verification code is for. <b>The purpose is a security boundary, not a label</b>: a code
/// and the ticket minted from it are only ever consumable by the flow that asked for them, because
/// every query in <c>IVerificationCodeRepository</c> filters on this column.
/// <para>
/// <see cref="BackOfficeAuth"/> scopes back-office registration separately from consumer auth, so a
/// consumer ticket cannot be consumed by back-office registration and vice versa.
/// <see cref="BackOfficeResetPassword"/> scopes the back-office forgot-password flow separately from
/// the consumer <see cref="ResetPassword"/>, so a ticket minted against a consumer account can never
/// reset a back-office password and vice versa. The two identity planes are physically separate
/// tables and must never gate each other.
/// </para>
/// <para>Text, not a PostgreSQL enum: the column is <c>text</c> and this class is the enforcement.</para>
/// </summary>
public static class VerificationPurposes
{
    /// <summary>Consumer registration and code login share one purpose, because at send time we
    /// deliberately do not know which one the caller will end up doing.</summary>
    public const string Auth = "auth";

    /// <summary>Back-office registration. Its own template and its own ticket scope.</summary>
    public const string BackOfficeAuth = "backoffice_auth";

    public const string ResetPassword = "reset_password";

    /// <summary>Back-office self-service password reset. Email only.</summary>
    public const string BackOfficeResetPassword = "backoffice_reset_password";

    /// <summary>Attaching a new phone or email to an account that already exists.</summary>
    public const string Bind = "bind";

    /// <summary>
    /// Whether the value is one this service issues codes for. The check exists so an unknown
    /// purpose is refused at the edge rather than silently creating a code row nothing can ever
    /// consume - and so the notification-template lookup downstream can never miss.
    /// </summary>
    public static bool IsKnown(string? purpose) => purpose is
        Auth or BackOfficeAuth or ResetPassword or BackOfficeResetPassword or Bind;
}
