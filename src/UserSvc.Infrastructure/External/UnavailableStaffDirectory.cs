using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.External;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The stand-in for the corporate staff directory until an adapter for the real upstream is
/// configured. It exists so the sign-in orchestration, the account-provisioning rules and the error
/// contract can be written once, in full, against a port that already has the shape the real
/// adapter will have - replacing the one registration is then the whole cutover.
/// <para>
/// <b>Both methods refuse, and on this port there is no third option.</b> The risk-control
/// placeholder can afford to allow, because the decision it stands in for is a throttle with
/// another limiter behind it. This one stands on an authentication path:
/// <see cref="IStaffDirectory.VerifyOtpAsync"/> is the <i>entire</i> credential check for staff who
/// have no local password. Answering "verified" would sign in anyone who typed any code, and
/// answering "not verified" would be a lie of a subtler kind - the client would be told its
/// one-time password was wrong, support would spend a day chasing a code delivery problem, and no
/// dashboard would ever show that nothing had been checked at all. Refusing is the only answer that
/// is both safe and honest.
/// </para>
/// <para>
/// 501, not 502: nothing upstream failed, because nothing upstream was asked. Calling it a bad
/// gateway would point an investigation at a vendor who is working perfectly, and calling it 500
/// would suggest a defect rather than a capability this deployment simply does not have yet.
/// </para>
/// </summary>
public sealed class UnavailableStaffDirectory(ILogger<UnavailableStaffDirectory> logger) : IStaffDirectory
{
    private const string UnavailableMessage =
        "Staff one-time-password sign-in is not available on this deployment.";

    public Task<StaffOtpVerification> VerifyOtpAsync(
        string staffId,
        string oneTimePassword,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Error, not warning: reaching this method means a sign-in route is live that this
        // deployment cannot serve, which is a routing or configuration mistake rather than a
        // client one. Neither the employee number nor the code is logged - the first is an
        // attacker-controlled identifier and the second is a credential.
        logger.LogError(
            "A staff one-time password was submitted for verification, but no staff directory is "
            + "configured. Either this sign-in route should not be exposed yet, or the upstream "
            + "adapter is missing from this environment.");

        throw new AppException(ErrorCodes.NotImplemented, UnavailableMessage, 501);
    }

    public Task<StaffProfile> GetStaffProfileAsync(string staffId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        logger.LogError(
            "An HR staff profile was requested, but no staff directory is configured. No account "
            + "can be provisioned or refreshed from upstream data on this deployment.");

        // Deliberately not NotFoundException. "No such employee" is an answer, and this component
        // has none to give: a 404 here would let a caller conclude the employee does not exist
        // when the truth is that nobody looked.
        throw new AppException(ErrorCodes.NotImplemented, UnavailableMessage, 501);
    }
}
