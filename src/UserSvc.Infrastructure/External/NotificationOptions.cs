using System.ComponentModel.DataAnnotations;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// Where the notification capability service lives (decision 01) and the few resilience knobs
/// worth turning per environment. Everything else about the pipeline is left at the standard
/// handler's defaults on purpose: an option nobody tunes is an option that rots.
/// <para>
/// Validated at startup, and the ranges are not decoration. <c>MaxRetryAttempts</c> is capped at
/// <c>[1, 5]</c> because the underlying strategy rejects <c>0</c> outright - it throws
/// <c>OptionsValidationException</c> at boot rather than quietly disabling retries - and because
/// the send path is user-facing, where the sixth attempt only makes a person stare at a spinner
/// longer.
/// </para>
/// <para>
/// The cross-field rules in <see cref="Validate"/> exist because no attribute expresses them and
/// each one guards a failure that is otherwise silent:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <c>AttemptTimeout</c> must be strictly less than <c>TotalRequestTimeout</c>. The resilience
/// library rejects only the <i>greater-than</i> case, so equality boots cleanly and then makes
/// <c>MaxRetryAttempts</c> dead configuration - the first attempt consumes the entire budget and a
/// retry can never start. Checking it here also means the boot failure names our option instead of
/// the library's internal validator.
/// </description></item>
/// <item><description>
/// <c>BaseAddress</c> must be an absolute http/https URI <b>ending in <c>/</c></b>, and
/// <c>SendDirectPath</c> must be relative and unrooted. This is the trap that costs an afternoon:
/// <see cref="Uri"/> resolution replaces the last segment of the base path, so
/// <c>https://gw.internal/notify</c> plus <c>api/v1/send</c> resolves to
/// <c>https://gw.internal/api/v1/send</c> - the prefix is dropped, no error is raised anywhere, and
/// the first symptom is a 404 from a gateway nobody suspects. A leading <c>/</c> on the path does
/// the same thing.
/// </description></item>
/// </list>
/// <para>
/// <c>BaseAddress</c> is <see cref="RequiredAttribute"/>, which rejects the empty string, so this
/// section must never be shipped in appsettings with <c>"BaseAddress": ""</c> as a placeholder -
/// that refuses to boot. Leave the key out of the base file and set it per environment.
/// </para>
/// </summary>
public sealed class NotificationOptions : IValidatableObject
{
    public const string SectionName = "Notification";

    /// <summary>Absolute base address of the notification service, trailing slash included: <c>https://notify.internal/</c>.</summary>
    [Required]
    public string BaseAddress { get; init; } = string.Empty;

    /// <summary>Path of the direct-send endpoint, relative to <see cref="BaseAddress"/> and without a leading slash.</summary>
    [Required]
    public string SendDirectPath { get; init; } = "api/v1/notifications/send-direct";

    /// <summary>Retries after the first failure. Zero is not expressible - the strategy rejects it at startup.</summary>
    [Range(1, 5)]
    public int MaxRetryAttempts { get; init; } = 2;

    /// <summary>Budget for a single attempt. Lowering it also widens the breaker sampling window; see the registration.</summary>
    [Range(typeof(TimeSpan), "00:00:01", "00:00:30")]
    public TimeSpan AttemptTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Budget for the whole call including retries and backoff. The caller waits this long at worst.</summary>
    [Range(typeof(TimeSpan), "00:00:02", "00:02:00")]
    public TimeSpan TotalRequestTimeout { get; init; } = TimeSpan.FromSeconds(15);

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!Uri.TryCreate(BaseAddress, UriKind.Absolute, out var parsed)
            || (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps))
        {
            yield return new ValidationResult(
                $"{SectionName}:{nameof(BaseAddress)} must be an absolute http or https URI.",
                [nameof(BaseAddress)]);
        }
        else if (!parsed.AbsolutePath.EndsWith('/'))
        {
            // A host-only address such as "https://notify.internal" already has AbsolutePath "/",
            // so this only ever fires on a base address that carries a path prefix - the case
            // where dropping it silently sends every notification to the wrong endpoint.
            yield return new ValidationResult(
                $"{SectionName}:{nameof(BaseAddress)} must end with '/'. Without it, Uri resolution "
                + "drops the last path segment and the request goes to the wrong endpoint with no "
                + "error anywhere.",
                [nameof(BaseAddress)]);
        }

        if (string.IsNullOrWhiteSpace(SendDirectPath)
            || SendDirectPath.StartsWith('/')
            || Uri.IsWellFormedUriString(SendDirectPath, UriKind.Absolute))
        {
            yield return new ValidationResult(
                $"{SectionName}:{nameof(SendDirectPath)} must be a relative path with no leading "
                + $"'/': a rooted or absolute value discards the path component of {nameof(BaseAddress)}.",
                [nameof(SendDirectPath)]);
        }

        if (AttemptTimeout >= TotalRequestTimeout)
        {
            yield return new ValidationResult(
                $"{SectionName}:{nameof(AttemptTimeout)} must be strictly less than "
                + $"{nameof(TotalRequestTimeout)}; if one attempt can consume the whole budget then "
                + $"{nameof(MaxRetryAttempts)} is configuration that can never take effect.",
                [nameof(AttemptTimeout), nameof(TotalRequestTimeout)]);
        }
    }
}
