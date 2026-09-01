using System.ComponentModel.DataAnnotations;

namespace UserSvc.Application.Features.Sessions;

/// <summary>Session and token lifetimes. Validated at startup: a bad value refuses to boot.</summary>
public sealed class AuthSessionOptions
{
    public const string SectionName = "AuthSession";

    /// <summary>
    /// Access-token lifetime. It doubles as the TTL of revocation-set entries, which is why that
    /// set only ever holds recently revoked sessions and never grows (decision 11).
    /// </summary>
    [Range(typeof(TimeSpan), "00:01:00", "01:00:00")]
    public TimeSpan AccessTokenLifetime { get; init; } = TimeSpan.FromMinutes(10);

    [Range(typeof(TimeSpan), "01:00:00", "90.00:00:00")]
    public TimeSpan RefreshTokenLifetime { get; init; } = TimeSpan.FromDays(30);

    /// <summary>Maximum active devices per user; the least recently seen one is dropped beyond this.</summary>
    [Range(1, 50)]
    public int MaxActiveDevices { get; init; } = 10;
}
