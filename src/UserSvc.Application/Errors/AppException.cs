namespace UserSvc.Application.Errors;

/// <summary>
/// An expected application error. The API layer maps it to RFC 9457 ProblemDetails (decision 09):
/// <see cref="StatusCode"/> becomes the HTTP status and <see cref="ErrorCode"/> becomes the
/// <c>errorCode</c> extension member.
/// <para>The message must be safe to show to the caller — it ends up in the response body.</para>
/// </summary>
public class AppException(string errorCode, string message, int statusCode = 400) : Exception(message)
{
    public string ErrorCode { get; } = errorCode;

    public int StatusCode { get; } = statusCode;
}

/// <summary>400 — the input was wrong; fix it and resubmit.</summary>
public sealed class BadRequestException(string errorCode, string message)
    : AppException(errorCode, message, 400);

/// <summary>401 — no valid credentials; the client should re-authenticate.</summary>
public sealed class UnauthorizedException(string errorCode, string message)
    : AppException(errorCode, message, 401);

/// <summary>403 — the caller is known but not allowed.</summary>
public sealed class ForbiddenException(string errorCode, string message)
    : AppException(errorCode, message, 403);

/// <summary>404 — the resource does not exist.</summary>
public sealed class NotFoundException(string errorCode, string message)
    : AppException(errorCode, message, 404);

/// <summary>409 — conflicts with the current state.</summary>
public sealed class ConflictException(string errorCode, string message)
    : AppException(errorCode, message, 409);

/// <summary>429 — rate or risk limit. <see cref="RetryAfter"/> is written to the <c>Retry-After</c> header.</summary>
public sealed class RateLimitedException(string errorCode, string message, TimeSpan retryAfter)
    : AppException(errorCode, message, 429)
{
    public TimeSpan RetryAfter { get; } = retryAfter;
}

/// <summary>502 — an upstream service failed; not the caller's fault.</summary>
public sealed class UpstreamException(string errorCode, string message)
    : AppException(errorCode, message, 502);
