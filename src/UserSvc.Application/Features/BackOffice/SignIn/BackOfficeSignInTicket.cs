using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Features.BackOffice.SignIn;

/// <summary>
/// The short-lived proof that somebody just authenticated to the back office, and what the sign-in
/// decided about them.
/// <para>
/// <b>Why a ticket exists at all.</b> Credentials in this service come out of the OpenIddict token
/// endpoint and nowhere else (decision 10), while the two things a back-office sign-in has to do -
/// judge a password or a one-time password, and answer with the tenant list the chooser is drawn
/// from - belong to a REST endpoint with the ProblemDetails error contract. Re-checking the
/// credential at the token endpoint is not an option for the corporate one-time-password path:
/// that code is single-use upstream, so the second check would be answered "already consumed" and
/// staff sign-in would never work. The ticket is what carries a completed authentication across
/// that boundary, and it is the same shape as
/// <see cref="SocialIdentity.SocialBindingTokenService"/>'s - signed, self-contained and held by
/// the client - for the same reason: nothing has to be remembered server side.
/// </para>
/// <para>
/// <b>It is a bearer credential for the account it names.</b> Hence a two-minute life, hence a
/// domain-separated HMAC, and hence <see cref="ExpiresAt"/> being written by the issuer rather
/// than read from the caller. What it is <i>not</i> is single-use: this service has no
/// consume-once store to put one in, so a stolen ticket can be redeemed more than once inside its
/// window. The cost is bounded by what redemption produces - a device session that supersedes the
/// previous one on the same device id, so the second redemption evicts the first rather than
/// running beside it - and by the window itself. See the follow-ups: a redemption marker in the
/// revocation store is the fix.
/// </para>
/// </summary>
/// <param name="UserId">The back-office account. An <c>iam.backend_users</c> id, never a consumer
/// one - the two number their accounts independently.</param>
/// <param name="ActorName">Display name, so the audit row written at redemption reads correctly
/// without a second database round trip.</param>
/// <param name="TokenVersion">The account's token version when the sign-in ran. It keys the
/// authority snapshot, so carrying it forward is what makes a permission taken away land on the
/// next request rather than at the next sign-in.</param>
/// <param name="ActType">
/// The context the sign-in resolved, or empty for a sign-in that has not chosen one.
/// <b>Empty is what makes the minted token a pre-tenant token</b>, and it is a positive statement
/// by the issuer rather than an absence: the decision tree writes it deliberately when it counted
/// two or more contexts to choose between.
/// </param>
/// <param name="ActCode">Company or supplier code for a tenant context; empty otherwise.</param>
/// <param name="ActDimension">Chosen dimension for a whole-dimension context; empty otherwise.</param>
/// <param name="ActIsAdmin">Whether the member row behind a tenant context holds an admin role.</param>
public sealed record BackOfficeSignInTicket(
    [property: JsonPropertyName("sub")] int UserId,
    [property: JsonPropertyName("nm")] string ActorName,
    [property: JsonPropertyName("ver")] int TokenVersion,
    [property: JsonPropertyName("at")] string ActType,
    [property: JsonPropertyName("ac")] string ActCode,
    [property: JsonPropertyName("ad")] string ActDimension,
    [property: JsonPropertyName("aa")] bool ActIsAdmin)
{
    /// <summary>Unix seconds. Set by <see cref="BackOfficeSignInTicketService.Issue"/>; whatever a
    /// caller supplies is overwritten.</summary>
    [JsonPropertyName("exp")]
    public long ExpiresAt { get; init; }

    /// <summary>
    /// True when this sign-in has not chosen a context and the token minted from it must therefore
    /// be a pre-tenant one.
    /// </summary>
    [JsonIgnore]
    public bool ContextRequired => ActType.Length == 0;

    /// <summary>
    /// The act claim this ticket resolves to, or null for a pre-tenant sign-in and for an account
    /// that holds no authority at all.
    /// <para>
    /// The two null cases are deliberately indistinguishable here: both mean "this token carries
    /// no context", which every guard in the back office reads as "holds nothing" rather than as
    /// "unrestricted". What separates them is the scope the token is granted, which is the
    /// redeemer's decision and not this record's.
    /// </para>
    /// </summary>
    public ActClaim? ToActClaim() =>
        ActType.Length == 0 ? null : new ActClaim(ActType, ActCode, ActDimension, ActIsAdmin);

    /// <summary>A ticket for a sign-in that must choose a context before it gets a credential.</summary>
    public static BackOfficeSignInTicket PreTenant(int userId, string actorName, int tokenVersion) =>
        new(userId, actorName, tokenVersion, string.Empty, string.Empty, string.Empty, false);

    /// <summary>A ticket for a sign-in that resolved to one context - or, when <paramref name="act"/>
    /// is null, to no authority at all.</summary>
    public static BackOfficeSignInTicket ForContext(
        int userId, string actorName, int tokenVersion, ActClaim? act) =>
        act is null
            ? PreTenant(userId, actorName, tokenVersion)
            : new(userId, actorName, tokenVersion, act.Type, act.Code, act.Dimension, act.IsAdmin);
}

/// <summary>
/// Mints and opens <see cref="BackOfficeSignInTicket"/>s.
/// <para>
/// <b>The key is read at the point of use, not in the constructor.</b> Reading
/// <see cref="IOptions{TOptions}.Value"/> eagerly is what makes merely constructing a type throw
/// when a section is unconfigured, and this type is constructed on the token endpoint's own
/// dependency graph - so an eager read would take <c>/connect/token</c> down for consumer sign-in
/// too, over a secret consumer sign-in does not use. A deployment with no key configured fails on
/// the back-office sign-in endpoints and nowhere else.
/// </para>
/// </summary>
public sealed class BackOfficeSignInTicketService(
    IOptions<BackOfficeSignInOptions> options, IClock clock)
{
    /// <summary>
    /// Domain separation label. It is mixed into every signature so a ticket can never be
    /// presented where some other HMAC-signed payload of this service is expected, and vice
    /// versa - the two would otherwise verify against each other the day they share a key.
    /// </summary>
    private const string Context = "usersvc/back-office-sign-in/v1";

    /// <summary>32 bytes. A shorter HMAC key is not a weaker ticket, it is a forgeable one, and
    /// the whole authentication decision rides on this signature.</summary>
    private const int MinimumKeyBytes = 32;

    public string Issue(BackOfficeSignInTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);

        var settings = options.Value;
        var key = ReadKey(settings);

        var payload = ticket with
        {
            ExpiresAt = (clock.UtcNow + settings.SignInTicketLifetime).ToUnixTimeSeconds(),
        };

        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, BackOfficeSignInJson.Default.BackOfficeSignInTicket);

        return Base64Url.EncodeToString(bytes) + "." + Base64Url.EncodeToString(Sign(key, bytes));
    }

    /// <summary>
    /// Verifies and decodes a ticket.
    /// <para>
    /// Every failure - malformed, forged, expired, or naming a nonsensical account - is the same
    /// <see cref="UnauthorizedException"/> with the same message. The redeeming grant turns that
    /// into one OAuth <c>invalid_grant</c>, so nothing about which of those four went wrong reaches
    /// a caller who did not already know.
    /// </para>
    /// </summary>
    /// <exception cref="UnauthorizedException">The ticket is not usable.</exception>
    /// <exception cref="AppException">This deployment has no ticket key configured.</exception>
    public BackOfficeSignInTicket Open(string ticket)
    {
        var key = ReadKey(options.Value);

        if (string.IsNullOrEmpty(ticket))
        {
            throw Invalid();
        }

        var separator = ticket.IndexOf('.', StringComparison.Ordinal);
        if (separator <= 0 || separator == ticket.Length - 1)
        {
            throw Invalid();
        }

        byte[] payloadBytes;
        byte[] signature;

        try
        {
            payloadBytes = Base64Url.DecodeFromChars(ticket.AsSpan(0, separator));
            signature = Base64Url.DecodeFromChars(ticket.AsSpan(separator + 1));
        }
        catch (FormatException)
        {
            throw Invalid();
        }

        // Fixed-time, and the signature is checked before the payload is even parsed: a parser run
        // on unauthenticated bytes is a parser run on attacker input.
        if (!CryptographicOperations.FixedTimeEquals(signature, Sign(key, payloadBytes)))
        {
            throw Invalid();
        }

        BackOfficeSignInTicket? payload;
        try
        {
            payload = JsonSerializer.Deserialize(
                payloadBytes, BackOfficeSignInJson.Default.BackOfficeSignInTicket);
        }
        catch (JsonException)
        {
            throw Invalid();
        }

        if (payload is null
            || payload.UserId <= 0
            || clock.UtcNow.ToUnixTimeSeconds() > payload.ExpiresAt)
        {
            throw Invalid();
        }

        // An act type this build does not recognise is treated as no context rather than passed
        // on: the context funnel answers an unknown type with a 500, and a value that reached us
        // through a signed payload an older build minted is data, not a server fault.
        return ActTypes.IsKnown(payload.ActType) || payload.ActType.Length == 0
            ? payload
            : payload with { ActType = string.Empty, ActCode = string.Empty, ActDimension = string.Empty, ActIsAdmin = false };
    }

    private static byte[] Sign(byte[] key, byte[] payload)
    {
        var buffer = new byte[Context.Length + payload.Length];
        Encoding.ASCII.GetBytes(Context, buffer);
        payload.CopyTo(buffer, Context.Length);

        return HMACSHA256.HashData(key, buffer);
    }

    /// <summary>
    /// Reads the configured key, or refuses with the section named.
    /// <para>
    /// 500 <c>NOT_CONFIGURED</c> and not <c>INTERNAL_ERROR</c>: an operator reading the response
    /// needs to know to go and look at the secrets rather than at the code, and the message names
    /// the exact key so nobody has to read this file to find out which one.
    /// </para>
    /// </summary>
    private static byte[] ReadKey(BackOfficeSignInOptions settings)
    {
        byte[] key;
        try
        {
            key = Convert.FromHexString(settings.SignInTicketKey);
        }
        catch (FormatException ex)
        {
            throw NotConfigured("it is not valid hex", ex);
        }

        return key.Length >= MinimumKeyBytes
            ? key
            : throw NotConfigured($"it is shorter than {MinimumKeyBytes} bytes ({MinimumKeyBytes * 2} hex characters)");
    }

    private static AppException NotConfigured(string reason, Exception? cause = null) => new(
        ErrorCodes.NotConfigured,
        $"Back-office sign-in is not configured on this deployment: "
        + $"{BackOfficeSignInOptions.SectionName}:{nameof(BackOfficeSignInOptions.SignInTicketKey)} "
        + $"is unusable because {reason}.",
        500,
        cause);

    private static UnauthorizedException Invalid() => new(
        ErrorCodes.InvalidToken,
        "The sign-in ticket has expired or is not valid. Sign in again.");
}

/// <summary>
/// Source-generated serialization for the ticket. Generated rather than reflective so the shape is
/// fixed at compile time: a reflective serializer would follow a property somebody adds tomorrow
/// straight into a signed credential.
/// </summary>
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.Never)]
[JsonSerializable(typeof(BackOfficeSignInTicket))]
internal sealed partial class BackOfficeSignInJson : JsonSerializerContext;
