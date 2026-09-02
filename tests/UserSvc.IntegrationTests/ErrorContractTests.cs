using System.Net;
using System.Text;
using System.Text.Json;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.IntegrationTests.Infrastructure;

namespace UserSvc.IntegrationTests;

/// <summary>
/// Decision 09 in the shape a client sees it: every failure is RFC 9457 with an <c>errorCode</c>
/// and a <c>traceId</c>, and every success is the bare DTO. These run over the whole pipeline
/// because that is where the contract can break - the 401 in particular never reaches
/// <c>AppExceptionHandler</c> and is filled in by <c>UseStatusCodePages</c> instead.
/// </summary>
public sealed class ErrorContractTests(ServiceFixture fixture) : IntegrationTest(fixture)
{
    private static readonly Uri ProfilePath = new("/api/v1/user/profile", UriKind.Relative);

    [RequiresDockerFact]
    public async Task AnUnauthenticatedRequestAnswers401ProblemJsonWithAnErrorCodeATraceIdAndAChallenge()
    {
        using var client = Fixture.CreateClient();
        using var response = await client.GetAsync(ProfilePath);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        response.Headers.WwwAuthenticate.ToString()
            .Contains("Bearer", StringComparison.Ordinal)
            .ShouldBeTrue(
                "RFC 6750 requires the challenge to name the scheme it wants; without it a client "
                + "cannot tell what kind of credential to obtain.");

        var problem = await ProblemDetailsBody.ReadAsync(response);

        problem.ContentType.ShouldBe(
            "application/problem+json",
            "An authentication challenge sets a status code and returns, leaving an empty body. "
            + "UseStatusCodePages is what keeps 'every failure is ProblemDetails' true for the two "
            + $"statuses clients hit most. Body was: {problem.Raw}");
        problem.ErrorCode.ShouldBe(ErrorCodes.Unauthorized);
        problem.TraceId.ShouldMatch(
            "^[0-9a-f]{32}$",
            "traceId is how a support ticket becomes a log query, so the shape is part of the "
            + "contract, not just its presence: the bare W3C trace id, which is what a trace "
            + "backend's search box and Serilog's {TraceId} both take. ASP.NET Core's own "
            + "ProblemDetails writer would otherwise leave the whole '00-<trace>-<span>-01' "
            + $"traceparent here. Body was: {problem.Raw}");
    }

    [RequiresDockerFact]
    public async Task TheTraceIdContinuesTheCallersTraceRatherThanStartingANewOne()
    {
        const string callerTraceId = "4bf92f3577b34da6a3ce929d0e0e4736";

        using var client = Fixture.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, ProfilePath);
        request.Headers.TryAddWithoutValidation(
            "traceparent", $"00-{callerTraceId}-00f067aa0ba902b7-01");

        using var response = await client.SendAsync(request);
        var problem = await ProblemDetailsBody.ReadAsync(response);

        problem.TraceId.ShouldBe(
            callerTraceId,
            "A traceId that is ours alone is worth little: the point of W3C trace context is that "
            + "the gateway, this service and everything downstream report one id for one user "
            + "action. Losing the inbound traceparent breaks a cross-service investigation into "
            + $"unlinkable halves. Body was: {problem.Raw}");
    }

    [RequiresDockerFact]
    public async Task AValidationFailureAnswers400WithThePopulatedProblemDetailsErrorsDictionary()
    {
        var userId = await Fixture.SeedUserAsync();
        using var client = Fixture.CreateDevClient(userId);

        using var payload = new StringContent(
            """{"residenceCountryCode":"usa"}""", Encoding.UTF8, "application/json");
        using var response = await client.PatchAsync(ProfilePath, payload);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        var problem = await ProblemDetailsBody.ReadAsync(response);

        problem.ContentType.ShouldBe("application/problem+json");
        problem.ErrorCode.ShouldBe(ErrorCodes.ValidationFailed);
        problem.ValidationErrorKeys.ShouldContain(
            "ResidenceCountryCode",
            "A validation failure that says only '400' forces the client to guess which field is "
            + $"wrong. Body was: {problem.Raw}");

        (await Fixture.QueryStringsAsync(
                "SELECT residence_country_code FROM identity.users WHERE id = @p0", userId))
            .ShouldBe(["TW"], "A rejected request must not have written anything.");
    }

    [RequiresDockerFact]
    public async Task ASuccessfulReadAnswersTheBareDtoWithNoEnvelopeAndAnIdSerializedAsAJsonNumber()
    {
        var userId = await Fixture.SeedUserAsync(nickname: "bare-dto");
        using var client = Fixture.CreateDevClient(userId);

        using var response = await client.GetAsync(ProfilePath);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        response.Content.Headers.ContentType?.MediaType.ShouldBe("application/json");

        var body = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        root.TryGetProperty("data", out _).ShouldBeFalse($"There is no envelope. Body was: {body}");
        root.TryGetProperty("success", out _).ShouldBeFalse($"There is no envelope. Body was: {body}");

        root.TryGetProperty("nickname", out var nickname).ShouldBeTrue(
            $"The response is the DTO itself, so its members sit at the root. Body was: {body}");
        nickname.GetString().ShouldBe("bare-dto");

        root.TryGetProperty("id", out var id).ShouldBeTrue();
        id.ValueKind.ShouldBe(
            JsonValueKind.Number,
            "An id is an integer and serializes as a JSON number. Shipping it as a string to "
            + $"pre-empt a future widening is a contract change made today for nothing. Body was: {body}");
        id.GetInt32().ShouldBe(userId);
    }
}
