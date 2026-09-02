namespace UserSvc.Application.Ports.Tenancy;

/// <summary>
/// The cached copy of an account's token version. Invalidated after a membership change so the
/// next request re-reads the real one rather than serving a stale authority surface for the
/// cache's lifetime.
/// </summary>
public interface ITokenVersionCache
{
    Task InvalidateAsync(int userId, CancellationToken cancellationToken);
}
