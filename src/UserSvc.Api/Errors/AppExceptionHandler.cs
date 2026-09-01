using System.Diagnostics;
using System.Globalization;
using FluentValidation;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using UserSvc.Application.Errors;
using UserSvc.Domain.Abstractions;

namespace UserSvc.Api.Errors;

/// <summary>
/// The single mapping point from exceptions to RFC 9457 ProblemDetails (decision 09).
/// <para>
/// Statuses are grouped by <b>what the client should do next</b>, not by what the error literally
/// says: 400 fix the input and resubmit · 401 re-authenticate · 403 stop trying · 409 state
/// conflict · 422 business rule violated.
/// </para>
/// <para>
/// <c>title</c> stays stable (it does not vary per request for a given <c>type</c>, so dashboards
/// can aggregate on it); <c>detail</c> is the sentence shown to the user, translated per
/// <c>X-Language</c>.
/// </para>
/// </summary>
public sealed class AppExceptionHandler(
    IProblemDetailsService problemDetailsService,
    ILogger<AppExceptionHandler> logger) : IExceptionHandler
{
    private const string TypeBase = "https://errors.usersvc.internal/";

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        var mapped = Map(exception);

        if (mapped.Status >= 500)
        {
            logger.LogError(exception, "Unhandled exception on {Path}", httpContext.Request.Path);
        }
        else
        {
            logger.LogWarning(
                "Request failed with {ErrorCode} ({Status}) on {Path}",
                mapped.ErrorCode, mapped.Status, httpContext.Request.Path);
        }

        var problem = new ProblemDetails
        {
            Type = TypeBase + mapped.ErrorCode.ToLowerInvariant().Replace('_', '-'),
            Title = mapped.Title,
            Status = mapped.Status,
            Detail = mapped.Detail,
            Instance = httpContext.Request.Path,
        };

        problem.Extensions["errorCode"] = mapped.ErrorCode;
        problem.Extensions["traceId"] = Activity.Current?.TraceId.ToString() ?? httpContext.TraceIdentifier;

        if (mapped.Errors is not null)
        {
            problem.Extensions["errors"] = mapped.Errors;
        }

        httpContext.Response.StatusCode = mapped.Status;

        if (mapped.RetryAfter is { } retryAfter)
        {
            httpContext.Response.Headers.RetryAfter =
                ((int)retryAfter.TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }

        if (mapped.Status == StatusCodes.Status401Unauthorized)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer";
        }

        return await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = problem,
            Exception = exception,
        });
    }

    private static MappedError Map(Exception exception) => exception switch
    {
        // The domain deliberately knows nothing about HTTP, so the status is assigned here:
        // well-formed request, broken business rule -> 422.
        DomainRuleException domain => new(
            StatusCodes.Status422UnprocessableEntity, domain.ErrorCode,
            "A business rule was violated.", domain.Message, null, null),

        RateLimitedException rateLimited => new(
            rateLimited.StatusCode, rateLimited.ErrorCode,
            "Too many requests.", rateLimited.Message, null, rateLimited.RetryAfter),

        AppException app => new(
            app.StatusCode, app.ErrorCode, TitleFor(app.StatusCode), app.Message, null, null),

        ValidationException validation => new(
            StatusCodes.Status400BadRequest, ErrorCodes.ValidationFailed,
            "One or more validation errors occurred.", "The request payload failed validation.",
            validation.Errors
                .GroupBy(e => e.PropertyName, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.Select(e => e.ErrorMessage).ToArray(), StringComparer.Ordinal),
            null),

        // Fallback: internal detail goes to the logs and never into the response body.
        _ => new(
            StatusCodes.Status500InternalServerError, ErrorCodes.InternalError,
            "An unexpected error occurred.", "The request could not be completed.", null, null),
    };

    private static string TitleFor(int status) => status switch
    {
        400 => "The request was invalid.",
        401 => "Authentication is required.",
        403 => "Access is denied.",
        404 => "The resource was not found.",
        409 => "The request conflicts with the current state.",
        502 => "An upstream service failed.",
        _ => "The request could not be completed.",
    };

    private sealed record MappedError(
        int Status,
        string ErrorCode,
        string Title,
        string Detail,
        Dictionary<string, string[]>? Errors,
        TimeSpan? RetryAfter);
}
