using System.Globalization;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Polly;
using UserSvc.Application.Errors;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The parts of talking to WeChat that both WeChat adapters need, in one place because getting
/// either of them subtly wrong is invisible until production.
/// </summary>
internal static class WechatResponseReader
{
    /// <summary>Enough of a body to identify what WeChat objected to; not enough to be a log flood.</summary>
    private const int MaxLoggedBodyLength = 1024;

    private const string UnreachableMessage =
        "WeChat could not be reached. Try signing in again in a moment.";

    /// <summary>
    /// Sends the request and deserializes the body.
    /// <para>
    /// <b>The body is read as a string and parsed by hand rather than through
    /// <c>ReadFromJsonAsync</c>, and that is not a stylistic choice.</b> WeChat serves JSON under
    /// <c>Content-Type: text/plain</c> on several of these endpoints. The typed reader validates
    /// the media type first and throws <see cref="NotSupportedException"/>, which would surface as
    /// an unhandled 500 on a response that parses perfectly well.
    /// </para>
    /// <para>
    /// Transport failures and the resilience pipeline's own verdicts become
    /// <see cref="UpstreamException"/>: nothing about the caller's request was wrong, so a 502 is
    /// what points the investigation at WeChat rather than at the user.
    /// </para>
    /// </summary>
    public static async Task<T> SendAsync<T>(
        HttpClient httpClient,
        HttpRequestMessage request,
        JsonTypeInfo<T> typeInfo,
        CancellationToken cancellationToken)
        where T : class
    {
        HttpResponseMessage response;

        try
        {
            response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw Unreachable(ex);
        }
        catch (ExecutionRejectedException ex)
        {
            // The pipeline's own answer: the total-request budget elapsed, the breaker is open, or
            // the call was shed. None of these derives from OperationCanceledException.
            throw Unreachable(ex);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw Unreachable(ex);
        }

        using (response)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                throw new UpstreamException(
                    ErrorCodes.UpstreamUnavailable,
                    UnreachableMessage,
                    new HttpRequestException(
                        string.Create(
                            CultureInfo.InvariantCulture,
                            $"WeChat answered {(int)response.StatusCode}: {Truncate(body)}")));
            }

            try
            {
                return JsonSerializer.Deserialize(body, typeInfo)
                       ?? throw new UpstreamException(
                           ErrorCodes.UpstreamUnavailable, UnreachableMessage);
            }
            catch (JsonException ex)
            {
                throw new UpstreamException(ErrorCodes.UpstreamUnavailable, UnreachableMessage, ex);
            }
        }
    }

    /// <summary>Builds the JSON POST body WeChat's newer endpoints take.</summary>
    public static HttpRequestMessage JsonPost<T>(string path, T payload, JsonTypeInfo<T> typeInfo) =>
        new(HttpMethod.Post, path) { Content = JsonContent.Create(payload, typeInfo) };

    public static UpstreamException Unreachable(Exception cause) =>
        new(ErrorCodes.UpstreamUnavailable, UnreachableMessage, cause);

    public static string Truncate(string body) =>
        body.Length <= MaxLoggedBodyLength ? body : body[..MaxLoggedBodyLength];
}
