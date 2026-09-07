namespace BuildingBlocks.Core.Errors;

/// <summary>
/// Base for expected application errors. Mapped to RFC 9457 ProblemDetails by the API layer:
/// <see cref="ErrorCode"/> and traceId are emitted as extension members, <see cref="StatusCode"/>
/// becomes the HTTP status. Messages must be safe to show to callers.
/// </summary>
public class AppException(string errorCode, string message, int statusCode = 400) : Exception(message)
{
    public string ErrorCode { get; } = errorCode;
    public int StatusCode { get; } = statusCode;
}

public sealed class NotFoundException(string resource, object key)
    : AppException("not_found", $"{resource} '{key}' was not found.", 404);

public sealed class ConflictException(string errorCode, string message)
    : AppException(errorCode, message, 409);

/// <summary>A domain invariant was violated; 422 keeps it distinct from request-shape errors (400).</summary>
public sealed class DomainRuleException(string errorCode, string message)
    : AppException(errorCode, message, 422);
