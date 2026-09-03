using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;
using UserSvc.Api.Controllers.BackOffice;

namespace UserSvc.Api.OpenApi;

/// <summary>
/// Declares the bearer scheme once per document, which is what puts the <b>Authorize</b> button in
/// Swagger UI.
/// <para>
/// Without it the published document says nothing about credentials at all: every operation reads
/// as anonymous, there is nowhere to paste a token, and "Try it out" answers 401 on the majority of
/// this service's surface with no hint why. The scheme is <c>http</c>/<c>bearer</c> rather than an
/// <c>apiKey</c> header so the UI adds the <c>Bearer </c> prefix itself — pasting a raw token is
/// what people actually do, and an apiKey scheme silently sends it without the prefix.
/// </para>
/// </summary>
internal sealed class BearerSecuritySchemeTransformer : IOpenApiDocumentTransformer
{
    /// <summary>The scheme's name in <c>components.securitySchemes</c>, and the key every
    /// operation's requirement refers to.</summary>
    public const string SchemeName = "bearerAuth";

    public Task TransformAsync(
        OpenApiDocument document,
        OpenApiDocumentTransformerContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(document);

        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>(StringComparer.Ordinal);

        document.Components.SecuritySchemes[SchemeName] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description =
                "An access token from POST /connect/token. Paste the token itself - Swagger adds the "
                + "\"Bearer \" prefix. Consumer tokens come from the device grant; back-office tokens "
                + "come from the sign-in ticket grants and additionally carry a "
                + $"'{BackOfficeScopes.BackOffice}' or '{BackOfficeScopes.PreTenant}' scope, which is "
                + "what the back-office routes check.",
        };

        return Task.CompletedTask;
    }
}

/// <summary>
/// Marks each operation that actually requires a credential, and says which policy it enforces.
/// <para>
/// <b>Read from the endpoint's own authorization metadata, never from a list kept here.</b> That is
/// the same discipline <see cref="RequestHeadersOperationTransformer"/> follows for the device
/// headers, and for the same reason: a hand-maintained list of "these endpoints need a token" is
/// wrong the first time somebody adds an endpoint, and wrong silently. Taking it from the metadata
/// means the document says <c>[Authorize]</c> exactly where the pipeline enforces it — including the
/// per-action <c>[AllowAnonymous]</c> that opens two of <c>PasskeyController</c>'s routes inside an
/// otherwise authenticated class.
/// </para>
/// <para>
/// The requirement is written per operation rather than once at document level. A document-wide
/// <c>security</c> would put a lock on the registration, verification and social-login endpoints
/// too, and those are the ones a caller reaches <i>before</i> having any token at all.
/// </para>
/// </summary>
internal sealed class BearerSecurityOperationTransformer : IOpenApiOperationTransformer
{
    public Task TransformAsync(
        OpenApiOperation operation,
        OpenApiOperationTransformerContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(context);

        var metadata = context.Description.ActionDescriptor.EndpointMetadata;

        // AllowAnonymous anywhere in the metadata wins, which is how AuthorizationMiddleware itself
        // decides: it short-circuits on the first IAllowAnonymous it finds and never consults the
        // policy. Mirroring that rule rather than "the last attribute wins" keeps the document
        // aligned with the pipeline on exactly the cases where the two attributes are both present.
        if (metadata.OfType<IAllowAnonymous>().Any())
        {
            return Task.CompletedTask;
        }

        var authorize = metadata.OfType<IAuthorizeData>().ToList();
        if (authorize.Count == 0)
        {
            return Task.CompletedTask;
        }

        // The host document has to be handed to the reference. Without it the requirement
        // serialises as a bare {} - present in the JSON, and worth nothing: Swagger UI shows no
        // lock and sends no token, while the document still looks like it says something.
        operation.Security ??= [];
        operation.Security.Add(new OpenApiSecurityRequirement
        {
            [new OpenApiSecuritySchemeReference(
                BearerSecuritySchemeTransformer.SchemeName, context.Document)] = [],
        });

        var policies = authorize
            .Select(data => data.Policy)
            .Where(policy => !string.IsNullOrEmpty(policy))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();

        // Naming the policy is the difference between "you need a token" and "you need a token this
        // one cannot be": a consumer token satisfies a bare [Authorize] on every route in the
        // service, and on a back-office route it is refused by the policy rather than by the scheme.
        operation.Description = policies.Count == 0
            ? Append(operation.Description, "Requires an access token.")
            : Append(
                operation.Description,
                $"Requires an access token satisfying the {string.Join(" and ", policies)} policy.");

        return Task.CompletedTask;
    }

    private static string Append(string? description, string sentence) =>
        string.IsNullOrWhiteSpace(description) ? sentence : description.TrimEnd() + "\n\n" + sentence;
}
