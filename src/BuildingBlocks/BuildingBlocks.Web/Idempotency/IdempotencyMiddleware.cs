using System.Diagnostics;
using System.Globalization;
using BuildingBlocks.Core.Idempotency;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BuildingBlocks.Web.Idempotency;

/// <summary>
/// Replays stored responses for duplicate unsafe requests (POST/PATCH by default) that carry the
/// idempotency header — the HTTP-side counterpart of the messaging inbox. The first request per
/// key executes; its successful (&lt;400) response (status, content type, Location, body) is
/// stored for <see cref="IdempotencyOptions.Retention"/> and replayed verbatim for duplicates,
/// marked with an Idempotency-Replayed header. Concurrent duplicates get 409 while the original
/// is in flight. Error responses are never stored, so the client may retry with the same key.
/// The key is scoped per caller + method + path; the request BODY is not fingerprinted —
/// reusing a key with a different payload replays the original response.
/// <para>
/// Failure policy: when the store itself is unreachable the request is refused with 503 rather
/// than executed unprotected. There is nothing underneath an idempotency key — with the store
/// down nobody knows whether this key already ran — so failing open would not degrade the
/// guarantee but delete it, silently, for exactly the writes a caller marked must-not-duplicate.
/// The 503 carries Retry-After; the client retries with the same key once the store is back.
/// </para>
/// </summary>
public sealed class IdempotencyMiddleware(
    RequestDelegate next,
    IIdempotencyStore store,
    IOptions<IdempotencyOptions> options,
    ILogger<IdempotencyMiddleware> logger)
{
    public const string ReplayedHeaderName = "Idempotency-Replayed";

    private static readonly TimeSpan StoreUnavailableRetryAfter = TimeSpan.FromSeconds(5);

    public async Task InvokeAsync(HttpContext context)
    {
        var opts = options.Value;
        if (!opts.Enabled
            || !opts.EffectiveMethods.Contains(context.Request.Method, StringComparer.OrdinalIgnoreCase)
            || !context.Request.Headers.TryGetValue(opts.HeaderName, out var headerValues))
        {
            await next(context);
            return;
        }

        var headerValue = headerValues.ToString();
        if (headerValue.Length is 0 or > 128)
        {
            await WriteProblemAsync(context, StatusCodes.Status400BadRequest, "idempotency_key_invalid",
                $"The {opts.HeaderName} header must be 1-128 characters long.");
            return;
        }

        var key = BuildKey(context, headerValue);

        IdempotencyBeginResult begin;
        try
        {
            begin = await store.TryBeginAsync(key, opts.InFlightTtl, context.RequestAborted);
        }
        catch (Exception ex) when (!context.RequestAborted.IsCancellationRequested)
        {
            // Fail closed, and loudly: see the class comment. Any exception from the store is a
            // store failure by contract (TryBegin has no other failure mode), including the
            // timeout types StackExchange.Redis does NOT derive from RedisException.
            logger.LogError(ex,
                "Idempotency store unavailable; refusing {Method} {Path} rather than executing it unprotected.",
                context.Request.Method, context.Request.Path);
            context.Response.Headers.RetryAfter =
                ((int)StoreUnavailableRetryAfter.TotalSeconds).ToString(CultureInfo.InvariantCulture);
            await WriteProblemAsync(context, StatusCodes.Status503ServiceUnavailable, "idempotency_store_unavailable",
                "The idempotency store is unavailable; retry with the same key.");
            return;
        }

        if (begin.Status == IdempotencyBeginStatus.Completed)
        {
            await ReplayAsync(context, begin.Response!);
            return;
        }

        if (begin.Status == IdempotencyBeginStatus.InFlight)
        {
            context.Response.Headers.RetryAfter =
                ((int)opts.InFlightTtl.TotalSeconds).ToString(CultureInfo.InvariantCulture);
            await WriteProblemAsync(context, StatusCodes.Status409Conflict, "idempotency_in_flight",
                "A request with the same idempotency key is still being processed.");
            return;
        }

        await ExecuteAndCaptureAsync(context, key, opts);
    }

    private async Task ExecuteAndCaptureAsync(HttpContext context, string key, IdempotencyOptions opts)
    {
        var originalBody = context.Response.Body;
        using var buffer = new MemoryStream();
        context.Response.Body = buffer;

        try
        {
            await next(context);
        }
        catch
        {
            // Free the claim so the client can retry; the exception handler writes the error.
            await store.AbandonAsync(key, CancellationToken.None);
            throw;
        }
        finally
        {
            context.Response.Body = originalBody;
        }

        if (context.Response.StatusCode >= StatusCodes.Status400BadRequest)
        {
            await store.AbandonAsync(key, CancellationToken.None);
        }
        else if (buffer.Length > opts.MaxBodyBytes)
        {
            logger.LogWarning(
                "Idempotency snapshot for {Path} skipped: response body of {Size} bytes exceeds the {Max} byte cap.",
                context.Request.Path, buffer.Length, opts.MaxBodyBytes);
            await store.AbandonAsync(key, CancellationToken.None);
        }
        else
        {
            var location = context.Response.Headers.Location.ToString();
            await store.CompleteAsync(
                key,
                new StoredIdempotentResponse(
                    context.Response.StatusCode,
                    context.Response.ContentType,
                    location.Length > 0 ? location : null,
                    buffer.ToArray()),
                opts.Retention,
                CancellationToken.None);
        }

        buffer.Position = 0;
        await buffer.CopyToAsync(originalBody, context.RequestAborted);
    }

    private static async Task ReplayAsync(HttpContext context, StoredIdempotentResponse stored)
    {
        context.Response.StatusCode = stored.StatusCode;
        if (stored.ContentType is not null)
        {
            context.Response.ContentType = stored.ContentType;
        }

        if (stored.Location is not null)
        {
            context.Response.Headers.Location = stored.Location;
        }

        context.Response.Headers[ReplayedHeaderName] = "true";
        await context.Response.Body.WriteAsync(stored.Body, context.RequestAborted);
    }

    /// <summary>Caller-scoped, mirroring the rate limiter: one tenant's keys can never collide with another's.</summary>
    private static string BuildKey(HttpContext context, string headerValue)
    {
        var caller = context.User.FindFirst("azp")?.Value
            ?? context.User.FindFirst("client_id")?.Value
            ?? context.User.FindFirst("sub")?.Value
            ?? context.Connection.RemoteIpAddress?.ToString()
            ?? "unknown";
        return $"{caller}:{context.Request.Method}:{context.Request.Path}:{headerValue}";
    }

    /// <summary>
    /// Through the host's <see cref="IProblemDetailsService"/> when one is registered, so the
    /// CustomizeProblemDetails hook (traceId, instance, localization) shapes these bodies exactly
    /// like every other error; a plain write is the fallback for hosts and tests without it.
    /// </summary>
    private static async Task WriteProblemAsync(HttpContext context, int statusCode, string errorCode, string title)
    {
        context.Response.StatusCode = statusCode;

        var problem = new Microsoft.AspNetCore.Mvc.ProblemDetails
        {
            Status = statusCode,
            Title = title,
            Instance = context.Request.Path,
        };
        problem.Extensions["errorCode"] = errorCode;

        var problemDetailsService = context.RequestServices?.GetService<IProblemDetailsService>();
        if (problemDetailsService is not null
            && await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
            {
                HttpContext = context,
                ProblemDetails = problem,
            }))
        {
            return;
        }

        problem.Extensions["traceId"] = Activity.Current?.TraceId.ToString() ?? context.TraceIdentifier;
        await context.Response.WriteAsJsonAsync(
            problem, options: null, contentType: "application/problem+json", context.RequestAborted);
    }
}
