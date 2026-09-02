namespace UserSvc.Application.Features.BackOffice.Accounts;

/// <summary>
/// Audit action names this slice writes that the shared IAM catalogue does not carry yet.
/// <para>
/// <b>One entry, and it should not stay here.</b> <c>UserSvc.Domain.Iam.IamAuditActions</c> is the
/// catalogue for everything else IAM records, and a second list of action names is how two spellings
/// of one action end up in the same table. It lives here only because that type belongs to another
/// slice's files; folding this constant into it is a move, not a change - the stored value is the
/// same string either way.
/// </para>
/// </summary>
internal static class BackOfficeAuditActions
{
    /// <summary>
    /// A back-office account changing its own password through the mailbox-proof flow.
    /// <para>
    /// Actor and target are the same account, and the entry carries no tenant: a credential belongs
    /// to the account, not to any membership it happens to hold. That is what distinguishes it from
    /// an administrator-driven reset, which is one person taking over another's credential and is
    /// audited under the acting administrator.
    /// </para>
    /// </summary>
    internal const string SelfPasswordReset = "SELF_PASSWORD_RESET";
}
