using FluentValidation;

namespace UserSvc.Application.Features.BackOffice.TestWhitelist;

/// <summary>
/// Shape checks for the add request. A missing body, a zero and a negative id are all refused here
/// rather than in the service, so the caller gets the field name back instead of a prose message.
/// <para>
/// Whether the id names an account that can still sign in is a database question, and it is asked
/// in the application service - which is also the only place that can answer it.
/// </para>
/// </summary>
public sealed class AddTestWhitelistRequestValidator : AbstractValidator<AddTestWhitelistRequest>
{
    public AddTestWhitelistRequestValidator() =>
        RuleFor(x => x.UserId)
            .GreaterThan(0)
            .WithMessage("A consumer account id is required.");
}
