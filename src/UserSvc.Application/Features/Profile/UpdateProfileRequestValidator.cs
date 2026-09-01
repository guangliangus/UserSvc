using FluentValidation;

namespace UserSvc.Application.Features.Profile;

/// <summary>
/// Length and format checks live in code, not in column widths (team DDL convention: every string
/// column is <c>text</c>). Failures are turned into the <c>errors</c> dictionary of a 400
/// ProblemDetails by the API layer's validation filter.
/// </summary>
public sealed class UpdateProfileRequestValidator : AbstractValidator<UpdateProfileRequest>
{
    public UpdateProfileRequestValidator()
    {
        RuleFor(x => x.FirstName).MaximumLength(64);
        RuleFor(x => x.LastName).MaximumLength(64);
        RuleFor(x => x.Nickname).MaximumLength(64);
        RuleFor(x => x.ResidenceCountryCode)
            .Matches("^[A-Z]{2}$")
            .When(x => !string.IsNullOrEmpty(x.ResidenceCountryCode))
            .WithMessage("Residence country code must be a two-letter ISO 3166-1 alpha-2 code.");
    }
}
