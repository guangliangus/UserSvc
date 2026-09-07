using System.Diagnostics;
using BuildingBlocks.Core.Errors;
using FluentValidation;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace BuildingBlocks.Web.ProblemDetails;

/// <summary>
/// Central error → RFC 9457 mapping. AppException subclasses carry their own status and
/// errorCode; FluentValidation failures become 400 with a field/messages dictionary;
/// everything else is a sanitized 500 (details stay in the logs, never in the response).
/// </summary>
public sealed class MsvcExceptionHandler(
    IProblemDetailsService problemDetailsService,
    ILogger<MsvcExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        var (statusCode, errorCode, title, validationErrors) = Map(httpContext, exception);

        if (statusCode >= 500)
        {
            logger.LogError(exception, "Unhandled exception on {Path}", httpContext.Request.Path);
        }
        else
        {
            logger.LogWarning("Request failed with {ErrorCode} ({StatusCode}) on {Path}: {Message}",
                errorCode, statusCode, httpContext.Request.Path, exception.Message);
        }

        var problemDetails = new Microsoft.AspNetCore.Mvc.ProblemDetails
        {
            Status = statusCode,
            Title = title,
            Instance = httpContext.Request.Path,
        };
        problemDetails.Extensions["errorCode"] = errorCode;
        problemDetails.Extensions["traceId"] =
            Activity.Current?.TraceId.ToString() ?? httpContext.TraceIdentifier;
        if (validationErrors is not null)
        {
            problemDetails.Extensions["errors"] = validationErrors;
        }

        httpContext.Response.StatusCode = statusCode;
        return await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = problemDetails,
            Exception = exception,
        });
    }

    private static (int StatusCode, string ErrorCode, string Title, Dictionary<string, string[]>? Errors) Map(
        HttpContext httpContext,
        Exception exception) => exception switch
    {
        AppException app => (app.StatusCode, app.ErrorCode, app.Message, null),

        ValidationException validation => (
            StatusCodes.Status400BadRequest,
            "validation_failed",
            "One or more validation errors occurred.",
            validation.Errors
                .GroupBy(e => e.PropertyName)
                .ToDictionary(g => g.Key, g => g.Select(e => e.ErrorMessage).ToArray())),

        _ when IsDbConcurrencyException(exception) => (
            StatusCodes.Status409Conflict,
            "concurrency_conflict",
            "The resource was modified by another request. Reload it and retry.",
            null),

        OperationCanceledException when httpContext.RequestAborted.IsCancellationRequested => (
            499, "client_closed_request", "The client closed the request.", null),

        _ => (StatusCodes.Status500InternalServerError, "internal_error", "An unexpected error occurred.", null),
    };

    /// <summary>
    /// Matched by type name so this layer stays free of an EF Core dependency (the entity
    /// conventions apply xmin concurrency tokens; conflicts surface from SaveChanges).
    /// Pinned by a unit test against the real exception type.
    /// </summary>
    private static bool IsDbConcurrencyException(Exception exception)
    {
        for (var type = exception.GetType(); type is not null; type = type.BaseType)
        {
            if (type.FullName == "Microsoft.EntityFrameworkCore.DbUpdateConcurrencyException")
            {
                return true;
            }
        }

        return false;
    }
}
