namespace UserSvc.Application.Features.Registration;

/// <summary>
/// Sign-up payload. The caller has already proved control of <see cref="Identifier"/> through the
/// verification slice and holds the ticket that proves it; this request spends that ticket.
/// <para>
/// No property is <c>required</c> on purpose. A missing member would then fail in the JSON
/// deserializer, which answers with a message about a CLR type; leaving them optional lets
/// <see cref="RegisterRequestValidator"/> produce the <c>errors</c> dictionary the client can
/// actually act on.
/// </para>
/// </summary>
public sealed record RegisterRequest
{
    /// <summary>Which kind of identifier is being registered: <c>PHONE</c> or <c>EMAIL</c>,
    /// matched case-insensitively.</summary>
    public string IdentityType { get; init; } = string.Empty;

    /// <summary>The phone number or email address that was verified.</summary>
    public string Identifier { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    /// <summary>The single-use ticket minted when the code was verified. Consumed inside the same
    /// transaction as the insert, so it dies with the account it created.</summary>
    public string VerificationTicket { get; init; } = string.Empty;

    public string? FirstName { get; init; }
    public string? LastName { get; init; }

    /// <summary>Left empty, a nickname is derived from the identifier (email local part) or falls
    /// back to the default member name.</summary>
    public string? Nickname { get; init; }

    public string? Avatar { get; init; }
}

/// <summary>
/// The account that was just created. It is deliberately <b>not</b> a sign-in response: tokens are
/// OpenIddict's business (decision 10) and the client goes to the token endpoint next, so nothing
/// here is a credential.
/// </summary>
public sealed record RegisterResponse
{
    /// <summary>Serialized as a JSON number, like every other id in this service.</summary>
    public required int Id { get; init; }

    /// <summary>Always <c>ACTIVE</c> today - the identifier was verified moments ago, so there is
    /// nothing left to confirm. It is on the contract because a future flow (invite, manual
    /// review) can leave an account PENDING, and a client that never saw the field would treat
    /// that account as usable.</summary>
    public required string Status { get; init; }

    /// <summary>What the account will be displayed as - supplied, derived from the email local
    /// part, or the default member name.</summary>
    public required string Nickname { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}
