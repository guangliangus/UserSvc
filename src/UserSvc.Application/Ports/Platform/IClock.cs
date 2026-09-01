namespace UserSvc.Application.Ports.Platform;

/// <summary>
/// The source of time. It crosses no process boundary, but unit tests must be able to replace it,
/// which satisfies the second of the three port tests — so it is a port.
/// (Contrast: <c>IdentifierProtector</c> is a pure function and is not.)
/// </summary>
public interface IClock
{
    DateTimeOffset UtcNow { get; }
}
