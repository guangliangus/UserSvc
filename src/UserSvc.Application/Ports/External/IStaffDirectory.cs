namespace UserSvc.Application.Ports.External;

/// <summary>
/// The corporate staff directory: the upstream that authenticates an employee's one-time password
/// and that holds the HR record behind an employee number. It is what makes back-office sign-in
/// possible for group staff who have no local password.
/// <para>
/// It is a port for all three reasons at once - it crosses the network, unit tests must replace it,
/// and the implementation is a vendor API that will change. No adapter for the real upstream is
/// configured in this deployment, so the registered implementation is
/// <c>UnavailableStaffDirectory</c>, which <b>refuses</b>. The calling logic is written in full
/// against this interface, so swapping that one registration is the entire cutover.
/// </para>
/// <para>
/// <b>The two methods fail in deliberately different ways, and callers depend on the difference.</b>
/// An unreachable or broken upstream is an <see cref="Errors.UpstreamException"/> - nobody's
/// credentials were judged, so the caller must not phrase it as a failed sign-in. A one-time
/// password that was actually checked and found wrong is <i>not</i> an exception: it comes back as
/// <see cref="StaffOtpVerification.IsVerified"/> false, and the caller turns that into the sign-in
/// refusal. Collapsing the two would mean an outage reads to the user as "wrong password" and to
/// the dashboard as nothing at all.
/// </para>
/// <para>
/// <b>No implementation may answer <see cref="StaffOtpVerification.IsVerified"/> true that it did
/// not compute from the upstream's answer.</b> That boolean is the entire authentication decision
/// on this path - there is no password to check afterwards - so an optimistic default, a cached
/// success or a "the upstream is down, let them in" fallback is a full authentication bypass.
/// </para>
/// </summary>
public interface IStaffDirectory
{
    /// <summary>
    /// Asks the upstream whether this one-time password is currently valid for this employee.
    /// <para>
    /// The result is a judgement about the credential, not about the request: a wrong or expired
    /// code returns <see cref="StaffOtpVerification.IsVerified"/> false. An upstream that answered
    /// nothing intelligible is reported as an unavailable upstream rather than as a refusal - see
    /// the type-level note.
    /// </para>
    /// </summary>
    /// <param name="staffId">The corporate employee number the code was sent to.</param>
    /// <param name="oneTimePassword">The code the caller typed. Never logged, never audited.</param>
    /// <param name="cancellationToken">Cancels the upstream call.</param>
    /// <exception cref="Errors.AppException">The upstream could not be reached, refused the
    /// service's own credentials, or is not configured in this deployment. Distinct from a code
    /// that was checked and rejected.</exception>
    Task<StaffOtpVerification> VerifyOtpAsync(
        string staffId,
        string oneTimePassword,
        CancellationToken cancellationToken);

    /// <summary>
    /// The HR record for an employee number: the name, the mailbox and the department a
    /// back-office account is seeded and kept in step with.
    /// <para>
    /// HR is the system of record for these fields, so a caller refreshing an existing account
    /// overwrites what it holds - but only with values the upstream actually sent. An empty field
    /// means "HR said nothing", never "clear it".
    /// </para>
    /// </summary>
    /// <exception cref="Errors.NotFoundException">The upstream answered, and has no such employee.
    /// A real answer, not an outage.</exception>
    /// <exception cref="Errors.AppException">The upstream could not be reached or is not
    /// configured in this deployment.</exception>
    Task<StaffProfile> GetStaffProfileAsync(string staffId, CancellationToken cancellationToken);
}

/// <summary>
/// The upstream's verdict on one one-time password.
/// </summary>
/// <param name="IsVerified">
/// <b>The authentication decision itself.</b> True only when the upstream said so; see the note on
/// <see cref="IStaffDirectory"/> for why no implementation may originate a true.
/// </param>
/// <param name="ResultCode">The upstream's own outcome code, for logs and support tickets.</param>
/// <param name="InfoCode">Secondary upstream code - it distinguishes "expired" from "wrong" from
/// "locked out", none of which this service passes on to the client.</param>
/// <param name="ResultMessage">
/// The upstream's human-readable reason. <b>Log it, never return it</b>: it is text written by
/// another system about a failed credential check, and forwarding it would let the upstream decide
/// what our sign-in endpoint tells an attacker.
/// </param>
public sealed record StaffOtpVerification(
    bool IsVerified,
    string ResultCode,
    string InfoCode,
    string ResultMessage);

/// <summary>
/// One employee's HR record, in the fields a back-office account is built from.
/// </summary>
/// <param name="StaffCode">The employee number - the stable key, unchanged by a rename or a
/// transfer, which is why account matching starts here rather than at the mailbox.</param>
/// <param name="FullName">The employee's name as one string, as HR holds it. Split into given and
/// family name on the way into an account.</param>
/// <param name="Alias">Preferred display name, in its original casing. Empty for staff who have
/// none, in which case the mailbox's local part serves instead.</param>
/// <param name="Email">Corporate mailbox. The account's email identity is created from it, so an
/// empty value makes the profile unusable for provisioning rather than merely incomplete.</param>
/// <param name="EmploymentStatus">The upstream's employment-status code. Carried for a future gate
/// that refuses to sign in someone HR has already offboarded; nothing reads it yet.</param>
/// <param name="DepartmentNo">Department code.</param>
/// <param name="DepartmentName">Department name, for display.</param>
public sealed record StaffProfile(
    string StaffCode,
    string FullName,
    string Alias,
    string Email,
    string EmploymentStatus,
    string DepartmentNo,
    string DepartmentName);
