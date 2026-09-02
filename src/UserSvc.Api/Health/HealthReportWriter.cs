using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace UserSvc.Api.Health;

/// <summary>
/// The body of the three probe responses: the aggregate status, and one line per check naming it
/// and what it reported.
/// <para>
/// <b>It exists because the default writer answers with the single word "Unhealthy".</b> A status
/// code is enough for Kubernetes, which is why the default is what it is - but it is not enough for
/// the person who has just been paged because a deployment will not go ready, and it is the only
/// thing they can reach without a shell in the pod. Naming the failing check and forwarding its
/// description turns "readiness is red" into "readiness is red because
/// <c>IdentifierProtection:DataKey</c> does not decode to 32 bytes", which is the difference
/// between a five-minute fix and an incident.
/// </para>
/// <para>
/// <b>Only what a check chose to say.</b> Descriptions in this service are authored strings - the
/// Redis latency, the name of a missing setting - and never an exception's own message unless the
/// check decided it was safe. Exceptions, stack traces and durations are not written: they belong
/// in the log, which <c>HealthCheckService</c> already writes them to.
/// </para>
/// <para>
/// Written with <see cref="Utf8JsonWriter"/> rather than a serialized object graph, so there is no
/// reflection and no serializer configuration for a payload of three fields.
/// </para>
/// </summary>
public static class HealthReportWriter
{
    /// <summary>
    /// Writes <paramref name="report"/> to the response. The status code is not touched: the
    /// health-check middleware has already chosen it (200 for healthy and degraded, 503 for
    /// unhealthy), and a body that disagreed with it would be worse than no body at all.
    /// </summary>
    public static async Task WriteAsync(HttpContext context, HealthReport report)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.Response.ContentType = "application/json; charset=utf-8";

        using var buffer = new MemoryStream();

        await using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteString("status", report.Status.ToString());

            json.WriteStartArray("checks");

            // Ordered by name so that the same report always produces the same bytes: an operator
            // diffing two pods, and the tests that assert on this body, both need that.
            foreach (var entry in report.Entries.OrderBy(e => e.Key, StringComparer.Ordinal))
            {
                json.WriteStartObject();
                json.WriteString("name", entry.Key);
                json.WriteString("status", entry.Value.Status.ToString());

                if (!string.IsNullOrEmpty(entry.Value.Description))
                {
                    json.WriteString("description", entry.Value.Description);
                }

                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        // Buffered and then written in one go: the writer is synchronous over the stream, and
        // handing Kestrel a completed buffer keeps this off the response body's async path.
        await context.Response.Body.WriteAsync(buffer.ToArray(), context.RequestAborted);
    }
}
