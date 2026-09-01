using Xunit;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>
/// A <see cref="FactAttribute"/> that skips itself when Docker is absent.
/// <para>
/// xunit 2.9.3 has no runtime skip - <c>Assert.Skip</c> and <c>SkipUnless</c> are xunit v3 - but
/// <see cref="FactAttribute.Skip"/> is read at <b>discovery</b>, so assigning it in the
/// constructor works and costs one cached socket probe for the whole assembly.
/// </para>
/// </summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class RequiresDockerFactAttribute : FactAttribute
{
    public RequiresDockerFactAttribute()
    {
        if (DockerAvailability.SkipReason is { } reason)
        {
            Skip = $"Docker is required for the integration containers. {reason}";
        }
    }
}
