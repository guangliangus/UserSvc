using FluentValidation;
using UserSvc.Domain.Users;

namespace UserSvc.Application.Features.Registration;

/// <summary>
/// Shape checks only. Length limits live here rather than in column widths (team DDL convention:
/// every string column is <c>text</c>), and failures become the <c>errors</c> dictionary of a 400
/// ProblemDetails.
/// <para>
/// The format rules are a courtesy, not a security boundary: the real gate is the verification
/// ticket, which only matches the exact target a code was sent to. They exist so an obviously
/// malformed identifier is refused before it is hashed into a row nobody can search for.
/// </para>
/// </summary>
public sealed class RegisterRequestValidator : AbstractValidator<RegisterRequest>
{
    /// <summary>
    /// E.164 digits, with the leading plus optional - the same shape
    /// <c>VerificationRequestRules</c> accepts, on purpose: a number the send-code endpoint
    /// accepted must not be one this endpoint refuses, or the ticket it minted is unspendable.
    /// Punctuation is refused rather than tolerated for the same reason. The plus is optional and
    /// then dropped by <see cref="IdentifierNormalizer"/>, so both spellings are one account.
    /// </summary>
    // [0-9] rather than \d: .NET's \d also matches the fullwidth and Devanagari digits, and
    // those would pass this rule and then be dropped by IdentifierNormalizer, which keeps ASCII
    // digits only - silently registering a different number than the caller typed.
    private const string PhonePattern = @"^\+?[1-9][0-9]{1,14}$";

    private const string EmailPattern = @"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$";

    /// <summary>At least one letter and one digit, which is the rule the Go service enforced.</summary>
    private const string PasswordPattern = @"^(?=.*[A-Za-z])(?=.*\d).+$";

    public RegisterRequestValidator()
    {
        RuleFor(x => x.IdentityType)
            .NotEmpty()
            .Must(IdentifierNormalizer.IsSupportedIdentityType)
            .WithMessage($"Identity type must be {IdentityTypes.Phone} or {IdentityTypes.Email}.");

        RuleFor(x => x.Identifier)
            .NotEmpty()
            .MaximumLength(100);

        RuleFor(x => x.Identifier)
            .Matches(PhonePattern)
            .When(x => IdentifierNormalizer.IsPhone(x.IdentityType), ApplyConditionTo.CurrentValidator)
            .WithMessage("Phone number must be digits only, optionally with a leading +, for example +886912345678.");

        RuleFor(x => x.Identifier)
            .Matches(EmailPattern)
            .When(x => IdentifierNormalizer.IsEmail(x.IdentityType), ApplyConditionTo.CurrentValidator)
            .WithMessage("Email address is not a valid address.");

        RuleFor(x => x.Password)
            .NotEmpty()
            .MinimumLength(8)
            // Argon2id has no 72-byte truncation to hide behind, so the upper bound is ours to set.
            // Without one, a multi-megabyte password is a free way to make the server spend its
            // memory budget on one request.
            .MaximumLength(128)
            .Matches(PasswordPattern)
            .WithMessage("Password must contain at least one letter and one digit.");

        RuleFor(x => x.VerificationTicket).NotEmpty();

        // 100 to match the identifier and avatar caps, and because the Go original capped none of
        // these at all: a shorter limit invented here would refuse a registration the service being
        // replaced accepted, and a legal name is not something to be clever about.
        RuleFor(x => x.FirstName).MaximumLength(100);
        RuleFor(x => x.LastName).MaximumLength(100);
        RuleFor(x => x.Nickname).MaximumLength(100);
        RuleFor(x => x.Avatar).MaximumLength(100);
    }
}
