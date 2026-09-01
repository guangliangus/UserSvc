using UserSvc.Application.Ports.Platform;

namespace UserSvc.Infrastructure.Platform;

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
