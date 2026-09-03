using System.ComponentModel.DataAnnotations;
using Shouldly;
using UserSvc.Infrastructure.Tasks;
using Xunit;

namespace UserSvc.UnitTests.Tasks;

/// <summary>
/// The shipped defaults, asserted as the contract they are.
/// <para>
/// Nothing else in the suite reads them: every other test in this folder sets the value it needs,
/// which is right for testing behaviour and useless for the one question a deployment asks - "what
/// happens if I configure nothing". These are the answers to that, and two of them are promises
/// made in prose elsewhere that were not true when this file was written.
/// </para>
/// </summary>
public sealed class TaskQueueOptionsTests
{
    /// <summary>
    /// The Go service's own defaults, carried so that a pod moved from one implementation to the
    /// other behaves the same before anybody edits a config map. <c>TaskTimeout</c> is absent
    /// because Go has none (its handlers get <c>context.Background()</c>), and
    /// <c>ReclaimInterval</c> carries Go's <c>FixerInterval</c> under this project's name.
    /// </summary>
    [Fact]
    public void TheShippedDefaultsAreTheGoServicesDefaults()
    {
        var options = new TaskQueueOptions();

        options.WorkerCount.ShouldBe(
            0, "Zero is the kill switch AND the shipped default: user-svc ships the queue dormant, as the Go service does.");
        options.MaxAttempts.ShouldBe(6);
        options.ShortPollInterval.ShouldBe(TimeSpan.FromSeconds(2));
        options.LongPollInterval.ShouldBe(TimeSpan.FromSeconds(10));
        options.StalePoppedTimeout.ShouldBe(TimeSpan.FromMinutes(10));
        options.ReclaimInterval.ShouldBe(TimeSpan.FromMinutes(1), "Go calls this FixerInterval.");
        options.DrainTimeout.ShouldBe(
            TimeSpan.FromSeconds(5), "Go's APP_SHUTDOWN_TIMEOUT, carried as the queue's own bound.");
    }

    /// <summary>
    /// The per-task deadline must leave a cancelled handler time to unwind before the reclaim may
    /// give its row to somebody else.
    /// <para>
    /// This is the test of a defect the defaults actually shipped with: both values were ten
    /// minutes, which is no margin at all, while the XML doc on
    /// <see cref="TaskQueueOptions.StalePoppedTimeout"/> claimed it was "comfortably longer than"
    /// the timeout. Measured on the real host with the stale timeout at 4 seconds, no per-task
    /// deadline at all, and a handler that does not return: one row was handed out four times in
    /// fifteen seconds with every copy still running, and those four copies took every worker slot
    /// on the pod, after which the queue made no further progress on anything. The margin is what
    /// keeps that the crash case rather than the normal case, so it is asserted rather than left
    /// to prose.
    /// </para>
    /// </summary>
    [Fact]
    public void ATaskMayNotRunForAsLongAsItsClaimMayStand()
    {
        var options = new TaskQueueOptions();

        options.TaskTimeout.ShouldBeGreaterThan(
            TimeSpan.Zero, "A default of zero would mean no deadline at all, which is the worst case for the margin below.");
        options.TaskTimeout.ShouldBeLessThan(
            options.StalePoppedTimeout,
            "A task allowed to run as long as a claim may stand is handed to a second worker while the first is still running.");
        (options.StalePoppedTimeout - options.TaskTimeout).ShouldBeGreaterThanOrEqualTo(
            options.TaskTimeout,
            "The unwind window should be at least as long as the work itself, not a few seconds of luck.");
    }

    /// <summary>
    /// Every default must satisfy the annotations on its own property.
    /// <para>
    /// The section is bound with <c>ValidateDataAnnotations</c> and deliberately no
    /// <c>ValidateOnStart</c>, so validation runs on the first read - inside the runner and the
    /// reclaim, which catch it and stop polling. A default that failed its own
    /// <see cref="RangeAttribute"/> would therefore take the queue out of every deployment that
    /// configured nothing, and the only evidence would be one error line naming the section.
    /// </para>
    /// </summary>
    [Fact]
    public void TheDefaultsSatisfyTheirOwnValidationAttributes()
    {
        var options = new TaskQueueOptions();
        var failures = new List<ValidationResult>();

        var valid = Validator.TryValidateObject(
            options, new ValidationContext(options), failures, validateAllProperties: true);

        valid.ShouldBeTrue(
            "A default that fails its own annotation disables the queue on any deployment that configures nothing: "
            + string.Join("; ", failures.Select(failure => failure.ErrorMessage)));
    }
}
