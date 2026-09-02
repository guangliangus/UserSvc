using System.Text.Json.Serialization;

namespace UserSvc.Application.Features.SocialIdentity;

/// <summary>
/// Source-generated serialization for the three payloads this slice puts on the wire or in a
/// column. Generated rather than reflective so the whole slice stays trimming- and AOT-clean, and
/// so the shapes are fixed at compile time - these are contracts, and a reflective serializer will
/// happily follow a property somebody adds tomorrow straight into a signed token.
/// </summary>
[JsonSourceGenerationOptions(
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
[JsonSerializable(typeof(ProviderDetails))]
[JsonSerializable(typeof(FirebaseBindingProposal))]
[JsonSerializable(typeof(OAuthStateService.StatePayload))]
internal sealed partial class SocialJson : JsonSerializerContext;
