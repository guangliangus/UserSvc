using System.Buffers.Text;
using System.Text.Json;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.External;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// Everything about a Firebase ID token that is arithmetic on strings: the shape check that runs
/// before the token reaches the SDK, reading the <c>firebase</c> claim, and folding the Firebase
/// user record into what the token already said.
/// <para>
/// Split out from <see cref="FirebaseTokenVerifier"/> because these are the parts worth testing
/// exhaustively and none of them needs a network, a credential or a Firebase project.
/// </para>
/// <para>
/// <b>The claims are re-read from the token payload rather than taken from the SDK's own claim
/// dictionary</b>, and that is deliberate. The SDK's dictionary holds whatever its internal JSON
/// stack produced for a nested object, which is an implementation detail that has changed across
/// its major versions; parsing the payload with <see cref="JsonElement"/> gives one shape that a
/// test can construct by hand. It is safe precisely because it happens <i>after</i> the SDK has
/// verified the signature - this code never decides whether a token is genuine, only what an
/// already-genuine one says.
/// </para>
/// </summary>
public static class FirebaseTokenClaims
{
    /// <summary>
    /// Checks that the value is three non-empty base64url segments before handing it to the SDK.
    /// <para>
    /// A truncated or double-encoded token would otherwise reach the SDK and come back as a
    /// generic parse failure indistinguishable from a bad signature, which sends whoever is
    /// debugging a broken client looking for a key-rotation problem that does not exist.
    /// </para>
    /// </summary>
    /// <returns>The decoded payload segment, as JSON text.</returns>
    /// <exception cref="UnauthorizedException">The value is not a well-formed JWT.</exception>
    public static string RequireWellFormed(string? idToken)
    {
        var token = idToken?.Trim() ?? string.Empty;
        var segments = token.Split('.');

        if (segments.Length != 3 || Array.Exists(segments, s => s.Length == 0))
        {
            throw Invalid();
        }

        try
        {
            foreach (var segment in segments)
            {
                Base64Url.DecodeFromChars(segment);
            }

            return System.Text.Encoding.UTF8.GetString(Base64Url.DecodeFromChars(segments[1]));
        }
        catch (FormatException)
        {
            throw Invalid();
        }
    }

    /// <summary>
    /// Reads the profile claims and the <c>firebase</c> block out of a verified payload.
    /// <para>
    /// Every field is optional. A token with no <c>firebase</c> claim, or one whose
    /// <c>identities</c> map does not list the sign-in provider, yields empty strings rather than
    /// an error: an absent provider subject costs the stale-uid fallback, and refusing the sign-in
    /// over it would be a far larger loss than the one it prevents.
    /// </para>
    /// </summary>
    public static FirebaseIdentity Read(string payloadJson, string uid)
    {
        JsonElement payload;

        try
        {
            using var document = JsonDocument.Parse(payloadJson);
            payload = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            throw Invalid();
        }

        var provider = string.Empty;
        var providerUid = string.Empty;

        if (payload.TryGetProperty("firebase", out var firebase)
            && firebase.ValueKind == JsonValueKind.Object)
        {
            provider = Text(firebase, "sign_in_provider");

            if (provider.Length > 0
                && firebase.TryGetProperty("identities", out var identities)
                && identities.ValueKind == JsonValueKind.Object
                && identities.TryGetProperty(provider, out var subjects)
                && subjects.ValueKind == JsonValueKind.Array)
            {
                foreach (var subject in subjects.EnumerateArray())
                {
                    if (subject.ValueKind == JsonValueKind.String
                        && subject.GetString() is { Length: > 0 } value)
                    {
                        providerUid = value;
                        break;
                    }
                }
            }
        }

        return new FirebaseIdentity(
            uid,
            provider,
            providerUid,
            Text(payload, "email"),
            payload.TryGetProperty("email_verified", out var verified)
            && verified.ValueKind == JsonValueKind.True,
            Text(payload, "name"),
            Text(payload, "picture"));
    }

    /// <summary>
    /// Fills in what the token left blank from the Firebase user record.
    /// <para>
    /// <b>Why the record is consulted at all:</b> Firebase writes the top-level profile fields when
    /// the user is created and only refreshes the per-provider entries afterwards. A uid that was
    /// pre-created by an admin, or linked across two providers, can therefore have an empty
    /// top-level name or address while the provider that just signed in knows both. Falling through
    /// to that provider's own entry is what stops those accounts from being created with a
    /// placeholder nickname.
    /// </para>
    /// <para>
    /// <b>The provider entry is chosen by matching the sign-in provider, never by taking the
    /// first.</b> An account linked to both Apple and Google lists both, in an order nothing
    /// guarantees, and taking the first would attach the wrong address to this sign-in about half
    /// the time.
    /// </para>
    /// <para>
    /// <b><see cref="FirebaseIdentity.EmailVerified"/> is never touched.</b> It describes what the
    /// credential in hand attested to; the record describes the account's state now. Letting the
    /// record raise it would mean a token that said "unverified" could sign in as verified.
    /// </para>
    /// </summary>
    public static FirebaseIdentity ApplyUserRecord(FirebaseIdentity identity, FirebaseUserProfile record)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(record);

        var email = record.Email.Trim();
        var name = record.Name.Trim();
        var picture = record.Picture.Trim();

        var matching = record.Providers.FirstOrDefault(p =>
            string.Equals(p.ProviderId, identity.Provider, StringComparison.Ordinal));

        if (matching is not null)
        {
            email = email.Length > 0 ? email : matching.Email.Trim();
            name = name.Length > 0 ? name : matching.Name.Trim();
            picture = picture.Length > 0 ? picture : matching.Picture.Trim();
        }

        return identity with
        {
            Email = email.Length > 0 ? email : identity.Email,
            Name = name.Length > 0 ? name : identity.Name,
            Picture = picture.Length > 0 ? picture : identity.Picture,
        };
    }

    private static string Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private static UnauthorizedException Invalid() => new(
        ErrorCodes.FirebaseIdTokenInvalid, "The Firebase sign-in token is not valid.");
}

/// <summary>
/// The Firebase user record, reduced to the four things this service reads. Declared here rather
/// than used through the SDK's own type so that <see cref="FirebaseTokenClaims.ApplyUserRecord"/>
/// can be tested without a Firebase project.
/// </summary>
public sealed record FirebaseUserProfile(
    string Email,
    string Name,
    string Picture,
    IReadOnlyList<FirebaseProviderProfile> Providers)
{
    public static readonly FirebaseUserProfile Empty = new(string.Empty, string.Empty, string.Empty, []);
}

/// <summary>One provider's view of the same person, as Firebase stores it.</summary>
public sealed record FirebaseProviderProfile(string ProviderId, string Email, string Name, string Picture);
