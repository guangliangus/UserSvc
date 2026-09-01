using System.Net;
using System.Text.Json;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>An RFC 9457 error response, parsed. Decision 09 says every failure - including the
/// 401 challenge - answers in this shape and carries <c>errorCode</c> and <c>traceId</c>.</summary>
internal sealed record ProblemDetailsBody(
    HttpStatusCode Status,
    string ContentType,
    string ErrorCode,
    string TraceId,
    string Detail,
    string Raw,
    JsonElement Root)
{
    /// <summary>Property names of the <c>errors</c> extension member, empty when it is absent.</summary>
    public IReadOnlyList<string> ValidationErrorKeys =>
        Root.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Object
            ? [.. errors.EnumerateObject().Select(property => property.Name)]
            : [];

    public static async Task<ProblemDetailsBody> ReadAsync(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);

        var raw = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(raw);
        var root = document.RootElement.Clone();

        return new ProblemDetailsBody(
            response.StatusCode,
            response.Content.Headers.ContentType?.MediaType ?? string.Empty,
            Read(root, "errorCode"),
            Read(root, "traceId"),
            Read(root, "detail"),
            raw,
            root);
    }

    private static string Read(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) ? value.GetString() ?? string.Empty : string.Empty;
}
