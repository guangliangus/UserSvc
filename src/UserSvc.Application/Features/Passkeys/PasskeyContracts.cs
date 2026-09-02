using System.Text.Json;
using System.Text.Json.Nodes;

namespace UserSvc.Application.Features.Passkeys;

/// <summary>
/// Begin a registration. The body may be omitted entirely - a client that has no label to suggest
/// has nothing to send.
/// </summary>
public sealed record PasskeyRegisterBeginRequest
{
    /// <summary>What to call the credential once it exists. Remembered with the ceremony, so a
    /// client that names the key up front need not repeat it at finish time.</summary>
    public string? Name { get; init; }
}

/// <summary>
/// What a begin call answers with, for both ceremonies.
/// <para>
/// <see cref="PublicKey"/> is a JSON object, not a string: it is the WebAuthn options structure and
/// the client passes it to <c>navigator.credentials</c> unchanged. Re-encoding it as a string would
/// force every client to parse it a second time, and the member name is the one WebAuthn uses.
/// </para>
/// </summary>
public sealed record PasskeyChallengeResponse
{
    public required string FlowId { get; init; }

    public required JsonNode PublicKey { get; init; }
}

/// <summary>Finish a registration by returning the authenticator's attestation.</summary>
public sealed record PasskeyRegisterFinishRequest
{
    public required string FlowId { get; init; }

    /// <summary>Overrides the label given at begin time. Optional.</summary>
    public string? Name { get; init; }

    /// <summary>
    /// The <c>PublicKeyCredential</c> the browser produced, passed through untouched. Modelled as
    /// raw JSON because it is the WebAuthn wire format and this service is not its author - every
    /// member of it is defined, parsed and validated by the FIDO2 library, and re-declaring the
    /// shape here would only create a second definition to drift from the first.
    /// </summary>
    public JsonElement Credential { get; init; }
}

/// <summary>The credential that was just created.</summary>
public sealed record PasskeyRegistrationResponse
{
    public required int Id { get; init; }

    public required string Name { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>
/// Begin a login. Both members may be omitted, which asks for a discoverable ceremony - the
/// authenticator offers whatever credentials it holds for this site and the account is only learned
/// when the assertion arrives.
/// </summary>
public sealed record PasskeyLoginBeginRequest
{
    /// <summary>A phone number or email address, when the client knows who is signing in. It only
    /// narrows the credential list; it is never confirmed to the caller.</summary>
    public string? Identifier { get; init; }

    /// <summary><c>phone</c> or <c>email</c>. Must accompany <see cref="Identifier"/>.</summary>
    public string? IdentityType { get; init; }
}

/// <summary>Finish a login by returning the authenticator's assertion.</summary>
public sealed record PasskeyLoginFinishRequest
{
    public required string FlowId { get; init; }

    /// <summary>The <c>PublicKeyCredential</c> assertion, passed through untouched. See
    /// <see cref="PasskeyRegisterFinishRequest.Credential"/>.</summary>
    public JsonElement Credential { get; init; }
}

/// <summary>
/// Proof that the holder of a registered passkey just authenticated.
/// <para>
/// <b>It carries no tokens, and that is this service's shape rather than an omission.</b>
/// OpenIddict owns token issuance (decision 10) and the token endpoint is the only place
/// credentials are minted, exactly as registration issues none either. The client exchanges this
/// outcome at <c>/connect/token</c>.
/// </para>
/// </summary>
public sealed record PasskeyLoginResponse
{
    public required int UserId { get; init; }

    /// <summary>Which credential signed, so a client can show "signed in with your iPhone".</summary>
    public required int PasskeyId { get; init; }

    public required string PasskeyName { get; init; }

    public required DateTimeOffset AuthenticatedAt { get; init; }
}

/// <summary>One row on the "your passkeys" screen.</summary>
public sealed record PasskeyResponse
{
    public required int Id { get; init; }

    public required string Name { get; init; }

    /// <summary>Null for a credential that has been registered but never used to sign in.</summary>
    public DateTimeOffset? LastUsedAt { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>Every credential the account holds. An account with none gets an empty list, not a 404.</summary>
public sealed record PasskeyListResponse
{
    public required IReadOnlyList<PasskeyResponse> Passkeys { get; init; }
}

/// <summary>Relabel a credential.</summary>
public sealed record RenamePasskeyRequest
{
    public required string Name { get; init; }
}

/// <summary>
/// What the API layer knows about the caller of an anonymous passkey endpoint and the application
/// layer does not. Only the address, and only to spend the login-begin budget against it.
/// </summary>
/// <param name="ClientIp">
/// May be blank when the peer address could not be determined; the budget then charges one shared
/// bucket rather than failing, which is the safe direction.
/// </param>
public sealed record PasskeyRequestContext(string ClientIp);
