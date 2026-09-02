using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Infrastructure.External;
using Xunit;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// The LINE verification adapter. The three defensive re-checks after LINE has already answered
/// are what the interesting cases here are about.
/// </summary>
public sealed class LineHttpClientTests
{
    private const string Verified =
        """
        {"iss":"https://access.line.me","sub":"line-sub-1","aud":"line-channel-1",
         "name":"Dana","picture":"https://line/pic.png","email":"dana@example.com"}
        """;

    private readonly StubHttpMessageHandler _transport = new();

    private LineHttpClient Sut(string channelId = "line-channel-1") => new(
        new HttpClient(_transport) { BaseAddress = new Uri("https://api.line.me/") },
        Options.Create(new LineOptions { ChannelId = channelId }),
        NullLogger<LineHttpClient>.Instance);

    [Fact]
    public async Task AVerifiedTokenYieldsTheSubjectAndProfile()
    {
        _transport.RespondsWithJson(Verified);

        var identity = await Sut().VerifyIdTokenAsync("id-token-1", "nonce-1", CancellationToken.None);

        identity.Sub.ShouldBe("line-sub-1");
        identity.Email.ShouldBe("dana@example.com");
        identity.Name.ShouldBe("Dana");
        identity.Picture.ShouldBe("https://line/pic.png");
    }

    /// <summary>
    /// The channel id and the nonce are what make LINE's answer mean anything: they are how LINE is
    /// asked to check the audience and the replay binding on our behalf.
    /// </summary>
    [Fact]
    public async Task TheChannelIdAndTheNonceAreSentToLine()
    {
        _transport.RespondsWithJson(Verified);

        await Sut().VerifyIdTokenAsync("id-token-1", "nonce-1", CancellationToken.None);

        _transport.Paths.ShouldHaveSingleItem().ShouldBe("/oauth2/v2.1/verify");

        var body = _transport.Bodies.ShouldHaveSingleItem();
        body.ShouldContain("id_token=id-token-1");
        body.ShouldContain("client_id=line-channel-1");
        body.ShouldContain("nonce=nonce-1");
    }

    [Fact]
    public async Task NoNonceMeansNoNonceParameterRatherThanAnEmptyOne()
    {
        _transport.RespondsWithJson(Verified);

        await Sut().VerifyIdTokenAsync("id-token-1", string.Empty, CancellationToken.None);

        _transport.Bodies.ShouldHaveSingleItem().ShouldNotContain("nonce=");
    }

    [Fact]
    public async Task AnErrorObjectIsARefusal()
    {
        _transport.RespondsWithJson(
            """{"error":"invalid_request","error_description":"id token expired"}""",
            HttpStatusCode.BadRequest);

        var thrown = await Should.ThrowAsync<LineRejectedException>(() =>
            Sut().VerifyIdTokenAsync("id-token-1", "nonce-1", CancellationToken.None));

        // LINE's description can quote the token, so it stays in the log and never in the message.
        thrown.Message.ShouldNotContain("id token expired");
    }

    [Fact]
    public async Task AFailureStatusWithNoErrorObjectIsStillARefusal()
    {
        _transport.RespondsWithJson("{}", HttpStatusCode.Unauthorized);

        await Should.ThrowAsync<LineRejectedException>(() =>
            Sut().VerifyIdTokenAsync("id-token-1", "nonce-1", CancellationToken.None));
    }

    /// <summary>
    /// A token minted for a different LINE channel verifies perfectly and belongs to somebody
    /// else's application. Without this check it would sign its holder in here.
    /// </summary>
    [Fact]
    public async Task ATokenIssuedForAnotherChannelIsRefused()
    {
        _transport.RespondsWithJson(
            """{"iss":"https://access.line.me","sub":"line-sub-1","aud":"someone-elses-channel"}""");

        await Should.ThrowAsync<LineRejectedException>(() =>
            Sut().VerifyIdTokenAsync("id-token-1", "nonce-1", CancellationToken.None));
    }

    [Fact]
    public async Task AnUnexpectedIssuerIsRefused()
    {
        _transport.RespondsWithJson(
            """{"iss":"https://evil.example.com","sub":"line-sub-1","aud":"line-channel-1"}""");

        await Should.ThrowAsync<LineRejectedException>(() =>
            Sut().VerifyIdTokenAsync("id-token-1", "nonce-1", CancellationToken.None));
    }

    [Fact]
    public async Task AResponseWithNoSubjectIsRefused()
    {
        _transport.RespondsWithJson("""{"iss":"https://access.line.me","aud":"line-channel-1"}""");

        await Should.ThrowAsync<LineRejectedException>(() =>
            Sut().VerifyIdTokenAsync("id-token-1", "nonce-1", CancellationToken.None));
    }

    [Fact]
    public async Task ABlankTokenNeverReachesTheNetwork()
    {
        await Should.ThrowAsync<LineRejectedException>(() =>
            Sut().VerifyIdTokenAsync("  ", "nonce-1", CancellationToken.None));

        _transport.Requests.ShouldBeEmpty();
    }

    /// <summary>
    /// The opposite of the WeChat adapter, deliberately. Verification happens <i>at</i> LINE, so
    /// "LINE said no" and "we could not ask LINE" both leave us holding a token nobody has vouched
    /// for. Reporting the second as an upstream fault would mean answering 502 to a forged token
    /// during an outage - the one moment a forgery would most like to be read as infrastructure
    /// noise.
    /// </summary>
    [Fact]
    public async Task AnUnreachableLineIsARefusalRatherThanAnUpstreamFailure()
    {
        _transport.Throws(new HttpRequestException("connection refused"));

        var thrown = await Should.ThrowAsync<LineRejectedException>(() =>
            Sut().VerifyIdTokenAsync("id-token-1", "nonce-1", CancellationToken.None));

        thrown.StatusCode.ShouldBe(400);
    }

    [Fact]
    public async Task AnUnparseableBodyIsARefusal()
    {
        _transport.RespondsWithJson("not json");

        await Should.ThrowAsync<LineRejectedException>(() =>
            Sut().VerifyIdTokenAsync("id-token-1", "nonce-1", CancellationToken.None));
    }

    /// <summary>
    /// The audience check is skipped only when no channel id is configured at all, which the
    /// options make impossible in a running deployment. It is asserted so that a future change to
    /// the guard is a deliberate one.
    /// </summary>
    [Fact]
    public async Task WithNoChannelIdConfiguredTheAudienceIsNotChecked()
    {
        _transport.RespondsWithJson(
            """{"iss":"https://access.line.me","sub":"line-sub-1","aud":"whatever"}""");

        var identity = await Sut(string.Empty).VerifyIdTokenAsync("t", "n", CancellationToken.None);

        identity.Sub.ShouldBe("line-sub-1");
    }
}
