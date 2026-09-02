using FluentValidation;

namespace UserSvc.Application.Features.BackOffice.SignIn;

/// <summary>
/// Shape checks for the password door.
/// <para>
/// <b>Deliberately thin.</b> The only thing worth refusing before the flow runs is a request that
/// cannot possibly identify anybody, because everything after this point either reads the database
/// or spends 30 ms of Argon2. In particular there is no password-complexity rule here: complexity
/// belongs on the endpoints that <i>set</i> a password, and applying it at sign-in would refuse an
/// account whose existing password predates the current rule - locking out the one person who
/// most needs to get in and change it.
/// </para>
/// </summary>
public sealed class BackOfficePasswordSignInRequestValidator : AbstractValidator<BackOfficePasswordSignInRequest>
{
    public BackOfficePasswordSignInRequestValidator()
    {
        RuleFor(x => x.Email).NotEmpty().MaximumLength(100);

        // An upper bound, and only an upper bound. Argon2id does not truncate its input, so an
        // unbounded password is a free way to make one anonymous request spend the server's memory
        // budget.
        RuleFor(x => x.Password).NotEmpty().MaximumLength(128);
    }
}

/// <summary>
/// Shape checks for the corporate one-time-password door.
/// <para>
/// Both fields are opaque strings belonging to the upstream: the employee number is the corporate
/// directory's own key and is not ours to reformat, and the code's length and alphabet are that
/// system's to choose. So the rules are presence and a sane ceiling, nothing more - a
/// pattern invented here would refuse a perfectly good credential the day the upstream lengthens
/// its codes.
/// </para>
/// </summary>
public sealed class BackOfficeStaffOtpSignInRequestValidator : AbstractValidator<BackOfficeStaffOtpSignInRequest>
{
    public BackOfficeStaffOtpSignInRequestValidator()
    {
        RuleFor(x => x.StaffId).NotEmpty().MaximumLength(64);
        RuleFor(x => x.OneTimePassword).NotEmpty().MaximumLength(64);
    }
}
