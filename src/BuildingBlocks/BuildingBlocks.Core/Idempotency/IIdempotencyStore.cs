namespace BuildingBlocks.Core.Idempotency;

/// <summary>
/// Response snapshot replayed for duplicate requests carrying the same idempotency key.
/// Only the Location header survives a replay (enough for 201 Created); other response
/// headers are re-derived or dropped.
/// </summary>
public sealed record StoredIdempotentResponse(int StatusCode, string? ContentType, string? Location, byte[] Body);

public enum IdempotencyBeginStatus
{
    /// <summary>This request claimed the key — execute, then Complete or Abandon.</summary>
    Started,

    /// <summary>Another request with the same key is currently executing.</summary>
    InFlight,

    /// <summary>A response snapshot exists; replay it without executing.</summary>
    Completed,
}

public sealed record IdempotencyBeginResult(IdempotencyBeginStatus Status, StoredIdempotentResponse? Response = null);

/// <summary>
/// Claim/replay storage behind HTTP idempotency keys (Redis implementation lives in
/// BuildingBlocks.Caching). TryBegin must be atomic: exactly one concurrent caller
/// per key observes Started.
/// </summary>
public interface IIdempotencyStore
{
    Task<IdempotencyBeginResult> TryBeginAsync(string key, TimeSpan inFlightTtl, CancellationToken cancellationToken = default);

    /// <summary>Stores the response snapshot, replacing this request's in-flight claim.</summary>
    Task CompleteAsync(string key, StoredIdempotentResponse response, TimeSpan retention, CancellationToken cancellationToken = default);

    /// <summary>Drops the claim without storing anything, so the caller may retry immediately.</summary>
    Task AbandonAsync(string key, CancellationToken cancellationToken = default);
}
