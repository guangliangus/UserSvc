using System.Text.Json;
using FluentValidation;
using UserSvc.Application.Features.Registration;
using UserSvc.Domain.Auth;

namespace UserSvc.Application.Features.Passkeys;

/// <summary>
/// The label is the only free text a client sends on this path, and the column that stores it is
/// the one non-<c>text</c> string column in the schema, so its bound is enforced here rather than
/// left to the database.
/// </summary>
public sealed class PasskeyRegisterBeginRequestValidator : AbstractValidator<PasskeyRegisterBeginRequest>
{
    public PasskeyRegisterBeginRequestValidator() =>
        RuleFor(x => x.Name).MaximumLength(UserPasskey.MaxNameLength);
}

/// <summary>
/// <see cref="PasskeyRegisterFinishRequest.Credential"/> is checked for being a JSON object and
/// nothing more. Its members are the WebAuthn wire format, and re-validating them here would be a
/// second, weaker copy of what the FIDO2 library does before it will verify anything.
/// </summary>
public sealed class PasskeyRegisterFinishRequestValidator : AbstractValidator<PasskeyRegisterFinishRequest>
{
    public PasskeyRegisterFinishRequestValidator()
    {
        RuleFor(x => x.FlowId).NotEmpty();
        RuleFor(x => x.Name).MaximumLength(UserPasskey.MaxNameLength);
        RuleFor(x => x.Credential)
            .Must(credential => credential.ValueKind == JsonValueKind.Object)
            .WithMessage("A WebAuthn credential object is required.");
    }
}

/// <summary>
/// The identifier is bounded and the type is restricted, but neither is <b>required</b>: omitting
/// both is how a client asks for a discoverable login. Note that this validator never refuses an
/// identifier for being unknown - that answer is deliberately withheld (see
/// <see cref="PasskeyAppService.BeginLoginAsync"/>).
/// <para>
/// <b>A blank type is as good as an absent one</b>, and the two must not be told apart here. The Go
/// contract is <c>omitempty,oneof=phone email</c>, so a client that sends
/// <c>{"identifier":"","identity_type":""}</c> - which several of them do, because an unfilled form
/// field serializes that way - is asking for a discoverable login and must get one rather than a
/// 400. The recognised spellings come from <see cref="IdentifierNormalizer"/> rather than a second
/// literal list, so this validator and the lookup that follows it cannot disagree about what
/// <c>PHONE</c> means.
/// </para>
/// </summary>
public sealed class PasskeyLoginBeginRequestValidator : AbstractValidator<PasskeyLoginBeginRequest>
{
    public PasskeyLoginBeginRequestValidator()
    {
        RuleFor(x => x.Identifier).MaximumLength(100);
        RuleFor(x => x.IdentityType)
            .Must(type => string.IsNullOrWhiteSpace(type) || IdentifierNormalizer.IsSupportedIdentityType(type))
            .WithMessage("Identity type must be 'phone' or 'email'.");
    }
}

public sealed class PasskeyLoginFinishRequestValidator : AbstractValidator<PasskeyLoginFinishRequest>
{
    public PasskeyLoginFinishRequestValidator()
    {
        RuleFor(x => x.FlowId).NotEmpty();
        RuleFor(x => x.Credential)
            .Must(credential => credential.ValueKind == JsonValueKind.Object)
            .WithMessage("A WebAuthn assertion object is required.");
    }
}

public sealed class RenamePasskeyRequestValidator : AbstractValidator<RenamePasskeyRequest>
{
    public RenamePasskeyRequestValidator() =>
        RuleFor(x => x.Name).NotEmpty().MaximumLength(UserPasskey.MaxNameLength);
}
