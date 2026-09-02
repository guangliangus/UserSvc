using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Security;

namespace UserSvc.Api.Health;

/// <summary>
/// Wired to <c>/health/ready</c> only, and the reasoning for that is the substance of this file.
/// <para>
/// <b>Readiness, because a process whose data-encryption key is malformed will never answer a
/// request correctly.</b> Almost every endpoint this service exposes hashes or encrypts an
/// identifier somewhere - sign-in, registration, verification, the back-office roster - so a
/// deployment carrying a broken <c>IdentifierProtection:DataKey</c> should be taken out of the load
/// balancer rather than left to fail requests one at a time. Readiness is the probe that means
/// "should traffic be routed to me", and the honest answer here is no.
/// </para>
/// <para>
/// <b>Never liveness, and not merely as a convention.</b> Liveness answers "is this process
/// wedged, should the orchestrator restart me", and a restart cannot repair a secret: the next
/// container reads the same value from the same source and dies the same way. Putting this check on
/// liveness would turn one mistyped secret into a permanent CrashLoopBackOff whose only record is
/// in the logs of containers that no longer exist. Liveness therefore carries no checks at all
/// (<c>Predicate = _ =&gt; false</c> in <c>Program.cs</c>) and must keep carrying none.
/// </para>
/// <para>
/// <b>Nor the startup validator, which is the other place this check could have gone.</b>
/// <c>IdentifierProtectionOptions</c> is registered with <c>ValidateOnStart()</c>, so a section
/// that is absent or empty already refuses the boot - <c>[Required]</c> can see "there is no
/// value". What it cannot see is whether the value it does have is a hex pepper and a 32-byte
/// base64 key; teaching it that would move this failure from "boots, reports unready, and says why
/// on a URL the platform already polls" to "does not boot", which is strictly harder to diagnose
/// for a fault that is not fixable by restarting. The split that follows is deliberate: startup
/// catches a section nobody configured, readiness catches a section somebody configured wrongly,
/// and liveness catches neither, because neither is a wedged process.
/// </para>
/// <para>
/// <b>Why the protector arrives as a factory.</b> <c>HealthCheckService</c> constructs each
/// registered check <i>outside</i> the try/catch that guards <c>CheckHealthAsync</c>, so a check
/// whose own construction throws does not produce an unhealthy result - it produces an unhandled
/// exception, and the probe becomes the 500 this check exists to replace. Taking
/// <c>Func&lt;IdentifierProtector&gt;</c> moves the construction inside the guard
/// (docs/architecture.md, "inject <c>Func&lt;T&gt;</c> not <c>T</c> when a client's construction
/// could fail"). <see cref="IdentifierProtector"/>'s constructor is total today; this is what keeps
/// the probe honest on the day somebody makes it eager again.
/// </para>
/// </summary>
public sealed class IdentifierProtectionHealthCheck(Func<IdentifierProtector> protector) : IHealthCheck
{
    private const string HealthyDescription =
        "Identifier protection key material decodes and is usable.";

    /// <summary>
    /// What an unrecognised failure reports. The two failures this check expects - an unbindable
    /// section and an unusable key - carry messages written to be read by whoever is holding the
    /// secrets, and those are forwarded verbatim. Anything else is a defect rather than a
    /// configuration fault, and the exception handler's rule applies to a probe body as much as to
    /// a response body: internal detail goes to the log, never onto the wire.
    /// </summary>
    private const string UnknownFailureDescription =
        "The identifier-protection key material could not be read. See the log for the failure.";

    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Resolving and probing are both inside the guard on purpose - see the class remarks.
            protector().EnsureUsable();

            return Task.FromResult(HealthCheckResult.Healthy(HealthyDescription));
        }
        catch (Exception ex)
        {
            // Deliberately broad. Anything this method lets escape stops being an unhealthy
            // readiness result and becomes an unhandled 500 on the one URL an operator uses to find
            // out what is wrong, which is the exact failure being fixed here.
            //
            // HealthCheckService logs the entry - description and exception - at Error, so there is
            // no logger of our own: a second line per poll would be the same fact several times a
            // second.
            return Task.FromResult(HealthCheckResult.Unhealthy(
                ex is AppException or OptionsValidationException
                    ? ex.Message
                    : UnknownFailureDescription,
                ex));
        }
    }
}
