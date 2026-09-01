namespace UserSvc.Application.Features.Sessions;

/// <summary>One row on the "signed-in devices" screen.</summary>
public sealed record DeviceSessionResponse
{
    public required string SessionId { get; init; }
    public string DeviceName { get; init; } = string.Empty;
    public string Platform { get; init; } = string.Empty;
    public string IpAddress { get; init; } = string.Empty;
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset LastSeenAt { get; init; }

    /// <summary>Whether this is the device making the current request, so the UI can label its
    /// button "Sign out" instead of "Sign out this device".</summary>
    public bool IsCurrent { get; init; }
}
