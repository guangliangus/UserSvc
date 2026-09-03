using Microsoft.AspNetCore.OpenApi;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;
using UserSvc.Api.Middleware;

namespace UserSvc.Api.OpenApi;

/// <summary>
/// Declares the request headers <see cref="RequestContextMiddleware"/> reads — and, on a gated
/// path, refuses the request over — as OpenAPI parameters.
/// <para>
/// <b>Without this they are invisible.</b> The gate is middleware, so nothing in the ApiExplorer's
/// model knows it exists, and a client generated from this document sends none of them. Turn
/// <see cref="RequestContextOptions.RequireDeviceHeadersFor"/> on and every such client breaks at
/// once with 400 <c>MISSING_HEADER</c>, against a document that described the request it sent as
/// well formed. The headers are worth documenting even while the gate is off, because
/// <c>X-Language</c> already decides which language an error sentence comes back in and
/// <c>X-Request-ID</c> already lands on audit rows.
/// </para>
/// <para>
/// <b><c>required</c> is the gate's own answer, not a second opinion.</b> It comes from the same
/// options and the same predicate the middleware calls, so the document cannot claim one thing
/// while the pipeline does another — the failure that would produce is a client written against a
/// document that never matched the service.
/// </para>
/// <para>
/// <b>Exempt paths are dropped entirely rather than listed as optional.</b> On
/// <c>/connect/token</c> an <c>X-Platform</c> header is not optional, it is meaningless: that
/// endpoint speaks OAuth and could not answer <c>MISSING_HEADER</c> even if it wanted to. Offering
/// the parameter there would document a contract nothing enforces.
/// </para>
/// </summary>
internal sealed class RequestHeadersOperationTransformer(
    IOptions<RequestContextOptions> options,
    ILogger<RequestHeadersOperationTransformer> logger) : IOpenApiOperationTransformer
{
    /// <summary>
    /// The headers, and whether the gate is what makes each one mandatory. <c>X-Device-Info</c> is
    /// listed but never gated: the middleware reads it, stores it when it parses as a JSON object
    /// and drops it otherwise, so a client that wants to send it deserves to see it — but no path
    /// has ever refused a request for its absence.
    /// </summary>
    private static readonly (string Name, bool Gated, string Description)[] Headers =
    [
        (RequestContextAccessor.PlatformHeader, true,
            "Client platform, normalised to lower case by the service. For example `ios`, `android` or `web`."),
        (RequestContextAccessor.DeviceIdHeader, true,
            "Stable per-installation device id. It identifies the device session a sign-in opens."),
        (RequestContextAccessor.RequestIdHeader, true,
            "The caller's own correlation id. It is written to this service's logs and to back-office audit rows, "
            + "so quoting it in a support ticket is what makes the request findable."),
        (RequestContextAccessor.LanguageHeader, true,
            "Preferred language tag, for example `zh-TW`. When it names a supported locale the error `detail` "
            + "comes back translated and the response carries `Content-Language`."),
        (RequestContextAccessor.DeviceInfoHeader, false,
            "Optional diagnostic metadata as a JSON object, plain or percent-encoded. "
            + "Anything that parses as neither is dropped rather than refused."),
    ];

    /// <summary>
    /// Read at the point of use and guarded, for the reason
    /// <c>tests/UserSvc.ArchitectureTests/OptionsReadSiteTests.cs</c> records: <c>.Value</c> is
    /// where validation runs, and a document generator that threw on a mistyped
    /// <c>RequestContext</c> section would take the whole OpenAPI endpoint down over a setting it
    /// only consults for a <c>required</c> flag. Falling back to the defaults documents the
    /// headers as optional, which is exactly what an unbound section means at run time.
    /// </summary>
    private RequestContextOptions Settings
    {
        get
        {
            try
            {
                return options.Value;
            }
            catch (Exception ex)
            {
                logger.LogError(
                    ex,
                    "The {Section} configuration section could not be bound; the OpenAPI document is "
                    + "describing the device headers as optional, which is how the pipeline behaves "
                    + "with the section absent.",
                    RequestContextOptions.SectionName);

                return RequestContextOptions.Defaults;
            }
        }
    }

    public Task TransformAsync(
        OpenApiOperation operation,
        OpenApiOperationTransformerContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(context);

        // RelativePath carries no leading slash; PathString and the middleware's predicates want one.
        var path = new PathString("/" + (context.Description.RelativePath ?? string.Empty));

        if (RequestContextMiddleware.IsExempt(path))
        {
            return Task.CompletedTask;
        }

        var gated = RequestContextMiddleware.IsGated(path, Settings.RequireDeviceHeadersFor);

        operation.Parameters ??= [];

        foreach (var (name, gatedHeader, description) in Headers)
        {
            operation.Parameters.Add(new OpenApiParameter
            {
                Name = name,
                In = ParameterLocation.Header,
                Required = gated && gatedHeader,
                Description = description,
                Schema = new OpenApiSchema { Type = JsonSchemaType.String },
            });
        }

        return Task.CompletedTask;
    }
}
