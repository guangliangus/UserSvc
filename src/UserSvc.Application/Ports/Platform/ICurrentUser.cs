namespace UserSvc.Application.Ports.Platform;

/// <summary>
/// The caller behind the current request, populated by the API layer from validated token claims.
/// The application layer knows nothing about HTTP or JWT — only who is calling.
/// </summary>
public interface ICurrentUser
{
    /// <summary>The token's <c>sub</c>. Null when unauthenticated.</summary>
    int? UserId { get; }

    /// <summary>The token's <c>sid</c> — the server-generated session id, and the only
    /// trustworthy basis for signing a device out (decision 11).</summary>
    string? SessionId { get; }

    int RequireUserId();
}
