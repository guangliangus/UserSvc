using System.ComponentModel.DataAnnotations;

namespace UserSvc.Application.Features.SocialIdentity;

/// <summary>
/// The settings the third-party sign-in flows need that are not any single provider's business:
/// the key that signs the two stateless tokens this slice mints, their lifetimes, and which
/// Firebase sign-in providers this deployment accepts.
/// <para>
/// <b><see cref="SigningKey"/> is a secret and is <see cref="RequiredAttribute"/> with no default
/// anywhere in appsettings.</b> A default would be worse than a missing value: every deployment
/// that forgot to set it would share one publicly known key, and an OAuth state is precisely the
/// thing an attacker wants to be able to forge. Missing, the host refuses to boot; that is the
/// intended behaviour, the same one <c>Redis:Configuration</c> and
/// <c>Notification:BaseAddress</c> already have.
/// </para>
/// </summary>
public sealed class SocialIdentityOptions
{
    public const string SectionName = "SocialIdentity";

    /// <summary>
    /// HMAC key for the OAuth state and the Firebase binding token, hex-encoded. At least 32 bytes
    /// (64 hex characters), because both tokens are the only thing standing between a caller and a
    /// forged sign-in context.
    /// </summary>
    [Required]
    [RegularExpression(
        "^(?:[0-9a-fA-F]{2}){32,}$",
        ErrorMessage = "SocialIdentity:SigningKey must be at least 32 bytes of hex (64 hex characters).")]
    public string SigningKey { get; init; } = string.Empty;

    /// <summary>
    /// How long an issued OAuth state stays usable. Short on purpose - the state exists to survive
    /// one redirect through a provider, not to be stored.
    /// </summary>
    [Range(typeof(TimeSpan), "00:01:00", "00:30:00")]
    public TimeSpan StateLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How long the Firebase binding token stays usable. It authorizes attaching a third-party
    /// account to an existing account, so it is sized as the credential it is: long enough for a
    /// person to read a consent screen, short enough that a copy found later is worthless.
    /// </summary>
    [Range(typeof(TimeSpan), "00:01:00", "00:15:00")]
    public TimeSpan BindingTokenLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Firebase sign-in providers this deployment accepts, lower-cased and matched exactly.
    /// <para>
    /// It is an allow-list rather than a block-list because Firebase will happily mint a token for
    /// any provider enabled in the console - including anonymous and custom-token sign-ins, which
    /// prove nothing about who is holding the phone. A provider nobody deliberately added here
    /// cannot open an account.
    /// </para>
    /// </summary>
    [MinLength(1)]
    public IReadOnlyList<string> AllowedFirebaseProviders { get; init; } =
        ["google.com", "apple.com", "facebook.com"];
}
