using System.ComponentModel.DataAnnotations;
using StackExchange.Redis;

namespace UserSvc.Infrastructure.Platform;

/// <summary>
/// Redis connection settings for the session revocation set (decision 11). Validated at startup:
/// a missing, blank or unparseable endpoint list and a blanked-out prefix all refuse to boot
/// rather than running degraded.
/// <para>
/// The endpoint list is checked by <see cref="Validate"/> rather than by an attribute, and that is
/// the whole reason this type implements <see cref="IValidatableObject"/>. Attributes cannot see a
/// typo inside the string: <c>Redis__Configuration=localhost:6379,typo=1</c> satisfies
/// <see cref="RequiredAttribute"/>, boots cleanly, and then throws <see cref="ArgumentException"/>
/// out of the multiplexer factory on the first request that touches a session — once per request,
/// forever, as a 500 with the readiness probe unable to explain it. Parsing during validation
/// moves that to the only place it is cheap to diagnose.
/// </para>
/// <para>
/// <see cref="KeyPrefix"/> carries <see cref="RequiredAttribute"/> as well as the pattern on
/// purpose. <see cref="RegularExpressionAttribute"/> short-circuits on null and empty, so the
/// pattern alone would let <c>Redis__KeyPrefix=</c> boot cleanly with no prefix at all — every
/// service on a shared Redis would then write into the same unprefixed key space and nothing
/// would report a fault.
/// </para>
/// </summary>
public sealed class RedisOptions : IValidatableObject
{
    public const string SectionName = "Redis";

    /// <summary>StackExchange.Redis endpoint list, for example <c>localhost:6379</c>.</summary>
    [Required]
    public string Configuration { get; init; } = string.Empty;

    /// <summary>
    /// Prefix applied to every key this service writes. Key prefixing is the <b>only</b> isolation
    /// mechanism available: <c>ConfigurationOptions.DefaultDatabase</c> is not one, because Redis
    /// Cluster exposes db 0 and nothing else. Colon-separated segments are allowed on purpose —
    /// a shared Redis usually needs the environment in the prefix (<c>usersvc:prod:</c>), and that
    /// is the same isolation argument one level down.
    /// </summary>
    [Required]
    [RegularExpression(
        "^[A-Za-z0-9._-]+(?::[A-Za-z0-9._-]+)*:$",
        ErrorMessage = "Redis:KeyPrefix must be one or more ':'-separated segments of letters, digits, "
                       + "'.', '-' or '_', and must end with ':' — for example 'usersvc:' or 'usersvc:prod:'.")]
    public string KeyPrefix { get; init; } = "usersvc:";

    /// <summary>Milliseconds to wait for the initial connection. StackExchange.Redis default: 5000.</summary>
    [Range(200, 30_000)]
    public int ConnectTimeoutMilliseconds { get; init; } = 2_000;

    /// <summary>
    /// Milliseconds an issued command may take before it is abandoned. StackExchange.Redis default:
    /// 5000 for both the sync and async paths — far too long to sit in front of token validation.
    /// </summary>
    [Range(50, 30_000)]
    public int OperationTimeoutMilliseconds { get; init; } = 500;

    /// <summary>
    /// Builds the multiplexer configuration. Written as a method rather than a raw connection
    /// string because four of these settings are wrong by default for this workload and each one
    /// needs its reason recorded next to it.
    /// </summary>
    public ConfigurationOptions ToConfigurationOptions()
    {
        var options = ConfigurationOptions.Parse(Configuration);

        // Defaults to true, which turns a Redis outage into a boot failure: Connect() throws and
        // the pod never comes up, even though revocation lookups are designed to fail open. False
        // lets the process start and reconnect in the background.
        options.AbortOnConnectFail = false;

        // Unit trap: ConnectTimeout, SyncTimeout and AsyncTimeout are milliseconds. (KeepAlive,
        // which we leave at its 60 default, is seconds.) These bound the reachable-but-slow Redis,
        // which the backlog policy below does nothing for — the command is issued normally and
        // simply takes its time.
        options.ConnectTimeout = ConnectTimeoutMilliseconds;
        options.SyncTimeout = OperationTimeoutMilliseconds;
        options.AsyncTimeout = OperationTimeoutMilliseconds;

        // The other failure shape, a Redis that is down, is not covered by those timeouts at all.
        // Measured against a refused endpoint: the default backlog policy queues each command and
        // surfaces RedisConnectionException after ~1000ms irrespective of AsyncTimeout, whereas
        // FailFast rejects in ~0ms. That second would be paid by every token validation for the
        // whole outage, to reach a read path that only wants to fail open anyway.
        //
        // The accepted cost: FailFast also rejects during the sub-second reconnect SE.Redis would
        // otherwise ride out by queueing, so a sign-out landing in that window returns 502 instead
        // of quietly succeeding. Its database row is already committed by then, so the session
        // still dies at the next refresh — a loud, retryable failure on the rare write beats a
        // one-second stall on every read.
        options.BacklogPolicy = BacklogPolicy.FailFast;

        return options;
    }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        // [Required] already reports the blank case; parsing "" on top of it would only add a
        // second, worse-worded message for the same mistake.
        if (string.IsNullOrWhiteSpace(Configuration))
        {
            yield break;
        }

        if (DescribeConfigurationFault() is { } fault)
        {
            yield return new ValidationResult(fault, [nameof(Configuration)]);
        }
    }

    /// <summary>
    /// Runs the real production path — <see cref="ToConfigurationOptions"/>, not a lookalike — so
    /// that any future setting able to throw is covered by startup validation for free.
    /// </summary>
    private string? DescribeConfigurationFault()
    {
        try
        {
            return ToConfigurationOptions().EndPoints.Count > 0
                ? null
                : "Redis:Configuration parses but names no endpoint.";
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            return $"Redis:Configuration is not a valid StackExchange.Redis configuration string: {ex.Message}";
        }
    }
}
