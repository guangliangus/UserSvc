using FluentValidation;
using UserSvc.Domain.BackOffice;

namespace UserSvc.Application.Features.BackOffice.Accounts;

/// <summary>
/// Shape checks for back-office registration. The real gate is the verification ticket, which only
/// matches the exact mailbox a code was sent to; these rules exist so an obviously malformed
/// request is refused before anything is hashed or written.
/// </summary>
public sealed class BackOfficeRegisterRequestValidator : AbstractValidator<BackOfficeRegisterRequest>
{
    public BackOfficeRegisterRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .MaximumLength(100)
            .Must(email => BackOfficeNames.IsEmail(email))
            .WithMessage("Email address is not a valid address.");

        RuleFor(x => x.Password)
            .NotEmpty()
            .MinimumLength(8)
            // Same upper bound as consumer registration, for the same reason: Argon2id has no
            // built-in input truncation, so an unbounded password is a free way to spend the
            // server's memory budget on one request.
            .MaximumLength(128)
            .Matches(BackOfficePasswordRules.Pattern)
            .WithMessage(BackOfficePasswordRules.Message);

        RuleFor(x => x.VerificationTicket).NotEmpty();

        RuleFor(x => x.FirstName).MaximumLength(100);
        RuleFor(x => x.LastName).MaximumLength(100);
        RuleFor(x => x.Avatar).MaximumLength(100);
    }
}

/// <summary>Shape checks for the self-service password reset.</summary>
public sealed class BackOfficePasswordResetRequestValidator : AbstractValidator<BackOfficePasswordResetRequest>
{
    public BackOfficePasswordResetRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .MaximumLength(100)
            .Must(email => BackOfficeNames.IsEmail(email))
            .WithMessage("Email address is not a valid address.");

        RuleFor(x => x.NewPassword)
            .NotEmpty()
            .MinimumLength(8)
            .MaximumLength(128)
            .Matches(BackOfficePasswordRules.Pattern)
            .WithMessage(BackOfficePasswordRules.Message);

        RuleFor(x => x.VerificationTicket).NotEmpty();
    }
}

/// <summary>
/// Shape checks for the directory query. The page size is capped here rather than clamped in the
/// service: a client asking for ten thousand rows has made a mistake worth telling it about, and
/// silently serving a hundred instead makes its pager arithmetic wrong.
/// </summary>
public sealed class BackOfficeUserListRequestValidator : AbstractValidator<BackOfficeUserListRequest>
{
    public BackOfficeUserListRequestValidator()
    {
        RuleFor(x => x.PageSize).LessThanOrEqualTo(100);

        RuleFor(x => x.Status)
            .Must(BackendUserStatuses.IsKnown)
            .When(x => !string.IsNullOrEmpty(x.Status))
            .WithMessage("Status must be PENDING, ACTIVE or DISABLED.");

        RuleFor(x => x.Search).MaximumLength(100);
    }
}

/// <summary>
/// Shape check for the super-administrator lever: the intent must be stated.
/// <para>
/// This is the one validator in the slice that is doing security work rather than politeness. The
/// request grants or removes ownership of the entire platform, and an absent field defaulting to
/// <c>false</c> would turn a malformed request - a client that renamed the property, a proxy that
/// dropped the body - into a silent revocation.
/// </para>
/// </summary>
public sealed class SetSuperAdminRequestValidator : AbstractValidator<SetSuperAdminRequest>
{
    public SetSuperAdminRequestValidator()
    {
        RuleFor(x => x.Enabled)
            .NotNull()
            .WithMessage("State whether the super-administrator identity should be enabled.");
    }
}

/// <summary>The password rule shared by every back-office flow that sets one: at least one letter
/// and one digit, which is what the service being replaced enforced.</summary>
internal static class BackOfficePasswordRules
{
    internal const string Pattern = @"^(?=.*[A-Za-z])(?=.*\d).+$";

    internal const string Message = "Password must contain at least one letter and one digit.";
}
