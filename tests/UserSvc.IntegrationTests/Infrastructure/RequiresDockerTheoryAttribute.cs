using Xunit;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>
/// The <see cref="TheoryAttribute"/> counterpart of <see cref="RequiresDockerFactAttribute"/>, and
/// it exists for the same reason: the skip has to be assigned in the constructor because xunit
/// 2.9.3 reads it at discovery time. A theory that inherited the fact attribute instead would be
/// discovered as a single case and silently ignore its inline data.
/// </summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class RequiresDockerTheoryAttribute : TheoryAttribute
{
    public RequiresDockerTheoryAttribute()
    {
        if (DockerAvailability.SkipReason is { } reason)
        {
            Skip = $"Docker is required for the integration containers. {reason}";
        }
    }
}
