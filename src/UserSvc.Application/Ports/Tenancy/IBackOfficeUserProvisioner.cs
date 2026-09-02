namespace UserSvc.Application.Ports.Tenancy;

/// <summary>The account details an administrator supplies when inviting somebody who has no
/// back-office account yet.</summary>
public sealed record NewAccountRequest(string Email, string Nickname, string FirstName, string LastName);

/// <summary>
/// Outcome of resolving the target of a membership write.
/// <para>
/// <c>ReusedAccount</c> is true when an existing account was found - by id, or by an e-mail that is
/// already registered; false means one was just created, which is the only case that produces a
/// password. <c>InitialPassword</c> is that one-time password, and it is <b>never</b> returned to
/// the API caller: it goes out by e-mail after the transaction commits, and is empty whenever an
/// account was reused.
/// </para>
/// </summary>
public sealed record ProvisionedTarget(int UserId, bool ReusedAccount, string InitialPassword);

/// <summary>
/// Finds or creates the back-office account a membership will hang off. Owned by the user
/// provisioning slice; tenancy only ever asks the question.
/// </summary>
public interface IBackOfficeUserProvisioner
{
    /// <summary>
    /// Exactly one of <paramref name="userId"/> and <paramref name="newAccount"/> is meaningful;
    /// the caller has already enforced that.
    /// </summary>
    Task<ProvisionedTarget> ResolveOrProvisionAsync(
        int userId, NewAccountRequest? newAccount, CancellationToken cancellationToken);
}
