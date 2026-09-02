using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Infrastructure.External;
using Xunit;

namespace UserSvc.UnitTests.RiskControl;

/// <summary>
/// The provider adapter's judgement, with the socket replaced and nothing else.
/// <para>
/// The split these tests defend is the whole contract: a provider that answered and found the token
/// wanting produces a <b>decision</b>, while a provider that could not answer produces an
/// <b>exception</b>. Both are refusals, but only the first is ordinary traffic - and neither may
/// ever be a pass.
/// </para>
/// </summary>
public sealed class RecaptchaClientTests
{
    private static readonly CaptchaAssessmentRequest Request =
        new("client-token", CaptchaPlatform.Web, "203.0.113.7", "curl/8.4.0");

    /// <summary>The platform vocabulary, duplicated here rather than referenced, because these
    /// tests describe the wire and must not move when the application layer's constants do.</summary>
    private static class CaptchaPlatform
    {
        public const string Web = "web";
        public const string Android = "android";
    }

    [Fact]
    public void WithNoSecretTheAdapterReportsItselfUnconfigured() =>
        Build(new RecaptchaOptions()).Client.IsConfigured.ShouldBeFalse();

    /// <summary>
    /// <b>The claim that an unconfigured deployment still boots, checked rather than asserted in a
    /// comment.</b> Nothing in this section is <c>[Required]</c>, so a host with no
    /// <c>Recaptcha</c> section at all binds the defaults, passes <c>ValidateOnStart</c> and
    /// starts. The failure is then local to the one endpoint that needs a secret. If somebody later
    /// marks a secret required, this test is what tells them they have moved a one-endpoint outage
    /// onto every endpoint.
    /// </summary>
    [Fact]
    public void AnEmptyConfigurationSectionStillPassesStartupValidation()
    {
        var options = new RecaptchaOptions();
        var results = new List<ValidationResult>();

        Validator.TryValidateObject(options, new ValidationContext(options), results, validateAllProperties: true)
            .ShouldBeTrue(string.Join("; ", results.Select(result => result.ErrorMessage)));

        options.HasAnySecret.ShouldBeFalse();
    }

    /// <summary>A secret that is set but points at a malformed endpoint is a mistake rather than an
    /// absence, so it does refuse to boot - the asymmetry the section's remarks promise.</summary>
    [Theory]
    [InlineData("https://www.google.com/recaptcha", "api/siteverify")]
    [InlineData("not-a-uri", "api/siteverify")]
    [InlineData("https://www.google.com/recaptcha/", "/api/siteverify")]
    public void AMalformedEndpointDoesRefuseToBoot(string baseAddress, string verifyPath)
    {
        var options = new RecaptchaOptions { BaseAddress = baseAddress, VerifyPath = verifyPath };
        var results = new List<ValidationResult>();

        Validator.TryValidateObject(options, new ValidationContext(options), results, validateAllProperties: true)
            .ShouldBeFalse();
    }

    /// <summary>
    /// The typed failure a deployment without a Google account gets. It is a 500 rather than a 502
    /// because nothing upstream failed - nothing upstream was asked - and it is thrown here, at the
    /// one endpoint that needs a provider, rather than at startup where it would take the whole
    /// service down over a capability almost nothing uses. The code is <see cref="ErrorCodes.NotConfigured"/>
    /// and not <see cref="ErrorCodes.InternalError"/>: this is a missing secret, so the response
    /// must point the operator at the key store rather than at the source, exactly as every other
    /// optional capability does (docs/architecture.md, "a missing capability may only break itself").
    /// </summary>
    [Fact]
    public async Task WithNoSecretAnAssessmentFailsTypedRatherThanQuietlyPassing()
    {
        var client = Build(new RecaptchaOptions()).Client;

        var ex = await Should.ThrowAsync<AppException>(() => client.AssessAsync(Request, CancellationToken.None));

        ex.StatusCode.ShouldBe(500);
        ex.ErrorCode.ShouldBe(ErrorCodes.NotConfigured);
        ex.Message.ShouldContain("Recaptcha");
    }

    [Fact]
    public async Task AGoodScorePasses()
    {
        var (client, handler) = Build(Configured());
        Respond(handler, """{"success":true,"score":0.9,"action":"verification","hostname":"app.example.com"}""");

        var assessment = await client.AssessAsync(Request, CancellationToken.None);

        assessment.Passed.ShouldBeTrue();
        assessment.Score.ShouldBe(0.9);
    }

    /// <summary>A low score is the system working, not a fault: it is a decision, and it must not
    /// surface as an exception that pages somebody.</summary>
    [Fact]
    public async Task ALowScoreIsADecisionRatherThanAnError()
    {
        var (client, handler) = Build(Configured());
        Respond(handler, """{"success":true,"score":0.1,"hostname":"app.example.com"}""");

        var assessment = await client.AssessAsync(Request, CancellationToken.None);

        assessment.Passed.ShouldBeFalse();
        assessment.Score.ShouldBe(0.1);
    }

    /// <summary>
    /// A v2 checkbox key returns no score at all. Treating an absent score as zero would refuse
    /// every token such a key ever issues.
    /// </summary>
    [Fact]
    public async Task AKeyThatProducesNoScorePassesOnTheOtherChecks()
    {
        var (client, handler) = Build(Configured());
        Respond(handler, """{"success":true,"hostname":"app.example.com"}""");

        (await client.AssessAsync(Request, CancellationToken.None)).Passed.ShouldBeTrue();
    }

    /// <summary>
    /// Without the action check, a token minted by the same site key on any other page of the site
    /// is spendable here - so a low-value form elsewhere becomes a token factory for this endpoint.
    /// </summary>
    [Fact]
    public async Task ATokenMintedForAnotherActionIsRefused()
    {
        var (client, handler) = Build(Configured(action: "verification"));
        Respond(handler, """{"success":true,"score":0.9,"action":"newsletter","hostname":"app.example.com"}""");

        (await client.AssessAsync(Request, CancellationToken.None)).Passed.ShouldBeFalse();
    }

    /// <summary>
    /// The hostname list is the only thing standing between us and a token minted on an attacker's
    /// page with our public site key, on any key whose domain verification is switched off.
    /// </summary>
    [Fact]
    public async Task ATokenMintedOnAnotherHostnameIsRefused()
    {
        var (client, handler) = Build(Configured(hostnames: ["app.example.com"]));
        Respond(handler, """{"success":true,"score":0.9,"hostname":"phish.example.net"}""");

        (await client.AssessAsync(Request, CancellationToken.None)).Passed.ShouldBeFalse();
    }

    /// <summary>A native-app token carries no hostname; refusing it for that would break every
    /// mobile client the moment somebody pins the web hostname list.</summary>
    [Fact]
    public async Task ATokenWithNoHostnameIsNotJudgedByTheHostnameList()
    {
        var (client, handler) = Build(Configured(hostnames: ["app.example.com"]));
        Respond(handler, """{"success":true,"score":0.9,"apk_package_name":"com.example.app"}""");

        (await client.AssessAsync(Request, CancellationToken.None)).Passed.ShouldBeTrue();
    }

    /// <summary>An expired, duplicated or forged token is the client's problem and produces an
    /// ordinary refusal.</summary>
    [Fact]
    public async Task ARejectedClientTokenIsADecision()
    {
        var (client, handler) = Build(Configured());
        Respond(handler, """{"success":false,"error-codes":["timeout-or-duplicate"]}""");

        (await client.AssessAsync(Request, CancellationToken.None)).Passed.ShouldBeFalse();
    }

    /// <summary>
    /// A wrong secret is our defect. Reporting it as a failed challenge would loop a blameless user
    /// forever on something they cannot pass, so it becomes a 500 with a log line naming the
    /// configuration section.
    /// </summary>
    [Fact]
    public async Task AWrongSecretIsOurFaultAndSaysSo()
    {
        var (client, handler) = Build(Configured());
        Respond(handler, """{"success":false,"error-codes":["invalid-input-secret"]}""");

        var ex = await Should.ThrowAsync<AppException>(() => client.AssessAsync(Request, CancellationToken.None));

        ex.StatusCode.ShouldBe(500);
    }

    /// <summary>An error code this build has never seen falls on the refusing side: a verdict the
    /// code cannot read is not a verdict.</summary>
    [Fact]
    public async Task AnUnrecognisedErrorCodeDoesNotPass()
    {
        var (client, handler) = Build(Configured());
        Respond(handler, """{"success":false,"error-codes":["some-future-code"]}""");

        (await client.AssessAsync(Request, CancellationToken.None)).Passed.ShouldBeFalse();
    }

    [Fact]
    public async Task AProviderOutageIsAnUpstreamFailure()
    {
        var (client, handler) = Build(Configured());
        Respond(handler, "upstream is down", HttpStatusCode.ServiceUnavailable);

        var ex = await Should.ThrowAsync<UpstreamException>(
            () => client.AssessAsync(Request, CancellationToken.None));

        ex.StatusCode.ShouldBe(502);
    }

    /// <summary>
    /// A 200 carrying something that is not a verdict - a captive portal, a proxy error page, a
    /// regional block - is an outage shape. It must not read as a pass.
    /// </summary>
    [Fact]
    public async Task AnUnreadableBodyIsAnOutageRatherThanAPass()
    {
        var (client, handler) = Build(Configured());
        Respond(handler, "<html>blocked</html>");

        await Should.ThrowAsync<UpstreamException>(() => client.AssessAsync(Request, CancellationToken.None));
    }

    /// <summary>
    /// The secret travels in the form body and never in the URL - query strings are logged by every
    /// proxy on the path - and the platform picks which secret is used, because provider keys are
    /// issued per platform.
    /// </summary>
    [Fact]
    public async Task TheSecretGoesInTheBodyAndFollowsThePlatform()
    {
        var (client, handler) = Build(Configured(androidSecret: "android-secret"));
        Respond(handler, """{"success":true,"score":0.9}""");

        await client.AssessAsync(Request with { Platform = CaptchaPlatform.Android }, CancellationToken.None);

        handler.LastRequestUri.ShouldNotContain("secret");
        handler.LastBody.ShouldContain("secret=android-secret");
        handler.LastBody.ShouldContain("response=client-token");
        handler.LastBody.ShouldContain("remoteip=203.0.113.7");
    }

    /// <summary>A deployment with one key keeps working: an unset platform secret falls back to the
    /// default rather than failing.</summary>
    [Fact]
    public async Task AnUnsetPlatformSecretFallsBackToTheDefaultOne()
    {
        var (client, handler) = Build(Configured());
        Respond(handler, """{"success":true,"score":0.9}""");

        await client.AssessAsync(Request with { Platform = CaptchaPlatform.Android }, CancellationToken.None);

        handler.LastBody.ShouldContain("secret=shared-secret");
    }

    private static RecaptchaOptions Configured(
        string? action = null,
        IReadOnlyList<string>? hostnames = null,
        string? androidSecret = null) => new()
    {
        Secret = "shared-secret",
        SecretAndroid = androidSecret ?? string.Empty,
        MinScore = 0.5,
        ExpectedAction = action ?? string.Empty,
        AllowedHostnames = hostnames ?? [],
    };

    private static Harness Build(RecaptchaOptions options)
    {
        var handler = new StubHandler();

        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri(options.BaseAddress, UriKind.Absolute),
        };

        return new Harness(
            new RecaptchaClient(httpClient, Options.Create(options), NullLogger<RecaptchaClient>.Instance),
            handler);
    }

    private static void Respond(StubHandler handler, string body, HttpStatusCode status = HttpStatusCode.OK)
    {
        handler.Status = status;
        handler.Body = body;
    }

    /// <summary>The adapter under test and the socket it was given, so a test can arrange one and
    /// assert on the other without a static registry between them.</summary>
    private sealed record Harness(RecaptchaClient Client, StubHandler Handler);

    /// <summary>The socket, replaced. It records what went out so the "the secret is never in the
    /// URL" assertion has something to look at.</summary>
    private sealed class StubHandler : HttpMessageHandler
    {
        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

        public string Body { get; set; } = "{}";

        public string LastBody { get; private set; } = string.Empty;

        public string LastRequestUri { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastRequestUri = request.RequestUri?.ToString() ?? string.Empty;
            LastBody = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);

            return new HttpResponseMessage(Status)
            {
                Content = new StringContent(Body, Encoding.UTF8, "application/json"),
            };
        }
    }
}
