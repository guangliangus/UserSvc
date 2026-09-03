using System.Text.Json;
using Shouldly;
using UserSvc.IntegrationTests.Infrastructure;

namespace UserSvc.IntegrationTests;

/// <summary>
/// The published OpenAPI document describes the headers <c>RequestContextMiddleware</c> actually
/// reads.
/// <para>
/// These run over the real document rather than over the transformer, because the thing worth
/// pinning is not "the class adds parameters" but "a client generated from what this service
/// publishes sends what this service expects". The gap they close was measured: before the
/// transformer existed the document declared <b>zero</b> header parameters across all 62 paths,
/// so a generated client sent none of the four - and the day
/// <c>RequestContext:RequireDeviceHeadersFor</c> is switched on in a deployment, every one of those
/// clients starts answering 400 <c>MISSING_HEADER</c> against a document that called its request
/// well formed.
/// </para>
/// </summary>
public sealed class OpenApiDocumentTests(ServiceFixture fixture) : IntegrationTest(fixture)
{
    private static readonly Uri DocumentPath = new("/openapi/v1.json", UriKind.Relative);
    private static readonly Uri BackOfficeDocumentPath = new("/openapi/back-office-v1.json", UriKind.Relative);

    /// <summary>The one route that belongs in both documents: it issues credentials for both
    /// planes, so filing it under either would leave the other's generated client unable to obtain
    /// a token.</summary>
    private const string SharedPath = "/connect/token";

    private static readonly string[] DeviceHeaders =
        ["X-Platform", "X-Device-ID", "X-Request-ID", "X-Language"];

    [RequiresDockerFact]
    public async Task AConsumerOperationDeclaresTheDeviceHeadersItsMiddlewareReads()
    {
        var operation = await OperationAsync("/api/v1/user/profile", "get");
        var headers = HeaderParameters(operation);

        foreach (var name in DeviceHeaders)
        {
            headers.Keys.ShouldContain(
                name,
                $"{name} is read by RequestContextMiddleware on every request and is refused over "
                + "when the gate is on, so a document that omits it describes an endpoint this "
                + "service does not serve.");
        }
    }

    [RequiresDockerFact]
    public async Task TheDeviceHeadersAreOptionalWhileTheGateIsOff()
    {
        var operation = await OperationAsync("/api/v1/user/profile", "get");
        var headers = HeaderParameters(operation);

        foreach (var name in DeviceHeaders)
        {
            headers[name].ShouldBeFalse(
                $"RequireDeviceHeadersFor is empty by default, so nothing refuses a request for a "
                + $"missing {name} and the document must not claim otherwise. The flag is read from "
                + "the same options the middleware uses precisely so the two cannot disagree.");
        }
    }

    [RequiresDockerFact]
    public async Task TheTokenEndpointIsExemptAndDeclaresNoDeviceHeaders()
    {
        var operation = await OperationAsync("/connect/token", "post");

        HeaderParameters(operation).ShouldBeEmpty(
            "/connect answers in OAuth's error shape and could not produce MISSING_HEADER even if "
            + "the gate covered it - RequestContextMiddleware exempts the prefix outright. Offering "
            + "the parameters here would document a rule nothing enforces.");
    }

    [RequiresDockerFact]
    public async Task TheTwoPlanesArePublishedAsSeparateDocuments()
    {
        var consumer = await PathsAsync(DocumentPath);
        var backOffice = await PathsAsync(BackOfficeDocumentPath);

        consumer.ShouldNotBeEmpty();
        backOffice.ShouldNotBeEmpty();

        consumer.Where(IsBackOfficePath).ShouldBeEmpty(
            "The consumer document is what the mobile app generates its client from. A back-office "
            + "path in it is an endpoint the app can call and must be told not to.");

        backOffice.Where(p => !IsBackOfficePath(p) && p != SharedPath).ShouldBeEmpty(
            "The back-office document is what the admin console generates its client from, and the "
            + "prefix is the whole rule for what belongs in it.");
    }

    [RequiresDockerFact]
    public async Task TheOnlyPathInBothDocumentsIsTheTokenEndpoint()
    {
        var consumer = await PathsAsync(DocumentPath);
        var backOffice = await PathsAsync(BackOfficeDocumentPath);

        consumer.Intersect(backOffice, StringComparer.Ordinal).ShouldBe(
            [SharedPath],
            ignoreOrder: true,
            customMessage:
            "Anything else appearing in both documents means the split has stopped being a "
            + "partition, and a client generator would emit the same operation twice.");
    }

    [RequiresDockerFact]
    public async Task BothDocumentsDeclareTheBearerSchemeThatPutsTheAuthorizeButtonInSwagger()
    {
        foreach (var document in new[] { DocumentPath, BackOfficeDocumentPath })
        {
            var scheme = (await DocumentAsync(document))
                .GetProperty("components").GetProperty("securitySchemes").GetProperty("bearerAuth");

            scheme.GetProperty("type").GetString().ShouldBe("http", $"{document}");
            scheme.GetProperty("scheme").GetString().ShouldBe(
                "bearer",
                "http/bearer is what makes Swagger UI add the \"Bearer \" prefix itself. An apiKey "
                + "scheme would send the pasted token raw and every call would answer 401.");
        }
    }

    [RequiresDockerFact]
    public async Task AnAuthenticatedOperationNamesTheSchemeRatherThanCarryingAnEmptyRequirement()
    {
        var operation = await OperationAsync("/api/v1/user/profile", "get");

        var requirement = operation.GetProperty("security").EnumerateArray().Single();

        requirement.EnumerateObject().Select(p => p.Name).ShouldBe(
            ["bearerAuth"],
            "A requirement built without the host document serialises as a bare {} - it is present, "
            + "it looks like the document says something, and it means nothing: no lock in the UI "
            + "and no token on the request. This assertion is the one that catches that.");
    }

    [RequiresDockerFact]
    public async Task AnEndpointReachedBeforeAnyTokenExistsCarriesNoSecurity()
    {
        var registration = await OperationAsync("/api/v1/auth/register", "post");

        registration.TryGetProperty("security", out _).ShouldBeFalse(
            "Registration is where a caller goes before holding any credential. A lock on it would "
            + "be a document-wide 'security' leaking onto the endpoints that cannot satisfy it.");
    }

    [RequiresDockerFact]
    public async Task APerActionAllowAnonymousBeatsTheClassItSitsIn()
    {
        var login = await OperationAsync("/api/v1/auth/passkey/login/begin", "post");

        login.TryGetProperty("security", out _).ShouldBeFalse(
            "PasskeyController is [Authorize] as a class and this action is [AllowAnonymous] - which "
            + "is how the pipeline treats it, so it is how the document must read it. Anything that "
            + "classified operations by the class attribute would get this exact route wrong.");
    }

    private async Task<JsonElement> DocumentAsync(Uri document)
    {
        using var client = Fixture.CreateClient();
        using var response = await client.GetAsync(document);

        response.IsSuccessStatusCode.ShouldBeTrue($"{document} answered {response.StatusCode}.");

        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    private static bool IsBackOfficePath(string path) =>
        path.StartsWith("/api/v1/back-office/", StringComparison.Ordinal);

    private async Task<IReadOnlyList<string>> PathsAsync(Uri document)
    {
        using var client = Fixture.CreateClient();
        using var response = await client.GetAsync(document);

        response.IsSuccessStatusCode.ShouldBeTrue($"{document} answered {response.StatusCode}.");

        var root = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

        return [.. root.GetProperty("paths").EnumerateObject().Select(p => p.Name)];
    }

    private async Task<JsonElement> OperationAsync(string path, string method)
    {
        using var client = Fixture.CreateClient();
        using var response = await client.GetAsync(DocumentPath);

        response.IsSuccessStatusCode.ShouldBeTrue(
            $"The OpenAPI document is mapped in Development and the test host runs there. Status was {response.StatusCode}.");

        var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();

        document.TryGetProperty("paths", out var paths).ShouldBeTrue();
        paths.TryGetProperty(path, out var item).ShouldBeTrue($"{path} is missing from the document.");
        item.TryGetProperty(method, out var operation).ShouldBeTrue($"{path} has no {method} operation.");

        return operation;
    }

    /// <summary>Header parameters of the operation, as name to <c>required</c>.</summary>
    private static Dictionary<string, bool> HeaderParameters(JsonElement operation)
    {
        if (!operation.TryGetProperty("parameters", out var parameters))
        {
            return [];
        }

        return parameters.EnumerateArray()
            .Where(p => p.TryGetProperty("in", out var location) && location.GetString() == "header")
            .ToDictionary(
                p => p.GetProperty("name").GetString() ?? string.Empty,
                p => p.TryGetProperty("required", out var required) && required.GetBoolean(),
                StringComparer.Ordinal);
    }
}
