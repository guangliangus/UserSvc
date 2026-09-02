using FluentValidation;

namespace UserSvc.Application.Features.Feedback;

/// <summary>
/// Shape checks for the submission form. Failures become the <c>errors</c> dictionary of a 400
/// ProblemDetails, and every field is reported at once rather than one per round trip - a form with
/// two empty boxes should light up both.
/// <para>
/// The category code is checked for presence only. Whether it names a real, active category is a
/// database question, and it is asked in the application service, which is also the only place that
/// can answer it without a second round trip.
/// </para>
/// </summary>
public sealed class SubmitFeedbackRequestValidator : AbstractValidator<SubmitFeedbackRequest>
{
    /// <summary>The same pattern the registration validator uses. Consistency matters more than
    /// cleverness here: an address this service accepts at sign-up must not be refused on a
    /// feedback form.</summary>
    private const string EmailPattern = @"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$";

    public SubmitFeedbackRequestValidator()
    {
        RuleFor(x => x.Type)
            .NotEmpty()
            .WithMessage("A feedback type is required.");

        // Trimmed, because whitespace is not feedback: a box containing four spaces has to be
        // refused with "this is required", not accepted and stored.
        RuleFor(x => x.Content)
            .Must(content => !string.IsNullOrWhiteSpace(content))
            .WithMessage("Feedback content is required.")
            .Must(content => FeedbackLimits.RuneCount(content?.Trim()) <= FeedbackLimits.MaxContentRunes)
            .WithMessage($"Feedback content must be at most {FeedbackLimits.MaxContentRunes} characters.");

        RuleFor(x => x.Name)
            .NotEmpty()
            .WithMessage("A contact name is required.")
            .Must(name => FeedbackLimits.RuneCount(name) <= FeedbackLimits.MaxNameRunes)
            .WithMessage($"The contact name must be at most {FeedbackLimits.MaxNameRunes} characters.");

        RuleFor(x => x.Email)
            .NotEmpty()
            .WithMessage("A contact email address is required.")
            .Must(email => FeedbackLimits.RuneCount(email) <= FeedbackLimits.MaxEmailRunes)
            .WithMessage($"The contact email address must be at most {FeedbackLimits.MaxEmailRunes} characters.")
            .Matches(EmailPattern)
            .When(email => !string.IsNullOrEmpty(email.Email), ApplyConditionTo.CurrentValidator)
            .WithMessage("The contact email address is not a valid address.");
    }
}
