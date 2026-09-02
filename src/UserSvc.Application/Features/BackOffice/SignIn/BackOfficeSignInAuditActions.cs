namespace UserSvc.Application.Features.BackOffice.SignIn;

/// <summary>
/// The two audit actions a sign-in writes, and the fixed set of reasons a refusal is recorded
/// under.
/// <para>
/// <b>They belong in <c>UserSvc.Domain.Iam.IamAuditActions</c> and should be moved there.</b> That
/// type is the catalogue for everything else IAM records, and a second list of action names is how
/// two spellings of one action end up in the same column. They live here only because that file
/// belongs to another slice's files while this one is being written; folding them in is a move,
/// not a change - the stored string is identical either way.
/// </para>
/// </summary>
public static class BackOfficeSignInAuditActions
{
    /// <summary>
    /// A completed sign-in. Written only when the sign-in resolved a context and will therefore
    /// produce a full credential: a sign-in that stopped at the context chooser is not finished,
    /// and the choice it goes on to make is recorded as <c>TENANT_SWITCH</c> by the endpoint that
    /// makes it. Recording both would count one sign-in twice.
    /// </summary>
    public const string SignIn = "LOGIN";

    /// <summary>
    /// A refused sign-in that resolved to a real account.
    /// <para>
    /// <b>Only attempts that named an existing account are recorded.</b> An unknown mailbox has no
    /// account row to anchor an entry to, and writing one anyway would persist an
    /// attacker-controlled identifier into the audit table - a log that can be filled with chosen
    /// text by anybody who can reach the endpoint.
    /// </para>
    /// </summary>
    public const string SignInFailed = "LOGIN_FAILED";
}

/// <summary>
/// Why a sign-in was refused, as the audit row records it.
/// <para>
/// <b>A fixed set, and the reason is the only thing recorded.</b> The password that was typed must
/// never travel anywhere near an audit trail - not truncated, not hashed, not "just the length" -
/// so the entry says which gate closed and nothing about what was presented to it.
/// </para>
/// </summary>
public static class BackOfficeSignInFailureReasons
{
    /// <summary>The account exists and the password did not verify. Also the answer when the
    /// account has no password at all: which of the two it was is a fact about the account, and
    /// telling them apart in the trail would tell them apart to anybody who can read it.</summary>
    public const string InvalidPassword = "INVALID_PASSWORD";

    public const string AccountDisabled = "ACCOUNT_DISABLED";

    /// <summary>A status that is neither ACTIVE, PENDING nor DISABLED. The database CHECK
    /// constraint does not allow one, which is exactly why a reason exists for it.</summary>
    public const string AccountInactive = "ACCOUNT_INACTIVE";

    /// <summary>An internal-origin account presented a mailbox outside the corporate allow-list.</summary>
    public const string InvalidDomain = "INVALID_DOMAIN";
}
