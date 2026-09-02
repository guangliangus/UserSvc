using System.Net;
using System.Net.Http.Headers;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// A scripted HTTP transport, so the provider adapters can be tested against the responses the
/// real providers actually send - including the ones that are only wrong in the body.
/// <para>
/// Written by hand rather than substituted because <c>SendAsync</c> is protected: the useful thing
/// about a stub here is the recorded request list, and a mock of a protected member gives a less
/// readable version of the same thing.
/// </para>
/// </summary>
internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _responses = new();

    public List<HttpRequestMessage> Requests { get; } = [];

    public List<string> Bodies { get; } = [];

    /// <summary>
    /// Queues a body served with <c>text/plain</c>, which is what WeChat actually sends for JSON.
    /// An adapter that used the typed JSON reader would throw on a response that parses perfectly
    /// well, so this is the default on purpose.
    /// </summary>
    public StubHttpMessageHandler RespondsWithJsonAsTextPlain(string json, HttpStatusCode status = HttpStatusCode.OK)
    {
        _responses.Enqueue(_ => Build(json, status, "text/plain"));

        return this;
    }

    public StubHttpMessageHandler RespondsWithJson(string json, HttpStatusCode status = HttpStatusCode.OK)
    {
        _responses.Enqueue(_ => Build(json, status, "application/json"));

        return this;
    }

    public StubHttpMessageHandler Throws(Exception exception)
    {
        _responses.Enqueue(_ => throw exception);

        return this;
    }

    /// <summary>The path and query of each request in order, for asserting what was actually called.</summary>
    public IReadOnlyList<string> Paths => [.. Requests.Select(r => r.RequestUri?.PathAndQuery ?? string.Empty)];

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Requests.Add(request);
        Bodies.Add(request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken));

        if (_responses.Count == 0)
        {
            throw new InvalidOperationException(
                $"The stub has no response left for {request.Method} {request.RequestUri}.");
        }

        return _responses.Dequeue()(request);
    }

    private static HttpResponseMessage Build(string json, HttpStatusCode status, string mediaType)
    {
        var content = new StringContent(json);
        content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);

        return new HttpResponseMessage(status) { Content = content };
    }
}
