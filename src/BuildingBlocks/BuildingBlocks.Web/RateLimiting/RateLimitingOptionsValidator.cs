using Microsoft.Extensions.Options;

namespace BuildingBlocks.Web.RateLimiting;

/// <summary>
/// Startup-time validation of the whole policy tree — DataAnnotations don't descend into
/// dictionaries, so the per-policy numbers are checked here (via ValidateOnStart).
/// </summary>
public sealed class RateLimitingOptionsValidator : IValidateOptions<RateLimitingOptions>
{
    public ValidateOptionsResult Validate(string? name, RateLimitingOptions options)
    {
        var failures = new List<string>();

        if (options.GlobalPolicy is { Length: > 0 } global && !options.Policies.ContainsKey(global))
        {
            failures.Add($"RateLimiting:GlobalPolicy '{global}' has no matching entry under RateLimiting:Policies.");
        }

        foreach (var (policyName, policy) in options.Policies)
        {
            var prefix = $"RateLimiting:Policies:{policyName}";

            if (policy.PermitLimit < 1)
            {
                failures.Add($"{prefix}:PermitLimit must be >= 1.");
            }

            if (policy.QueueLimit < 0)
            {
                failures.Add($"{prefix}:QueueLimit must be >= 0.");
            }

            if (policy.Type is RateLimitPolicyType.FixedWindow or RateLimitPolicyType.SlidingWindow
                && policy.WindowSeconds < 1)
            {
                failures.Add($"{prefix}:WindowSeconds must be >= 1.");
            }

            if (policy.Type is RateLimitPolicyType.SlidingWindow && policy.SegmentsPerWindow < 1)
            {
                failures.Add($"{prefix}:SegmentsPerWindow must be >= 1.");
            }

            if (policy.Type is RateLimitPolicyType.TokenBucket
                && (policy.TokensPerPeriod < 1 || policy.ReplenishmentPeriodSeconds < 1))
            {
                failures.Add($"{prefix}:TokensPerPeriod and ReplenishmentPeriodSeconds must be >= 1.");
            }
        }

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }
}
