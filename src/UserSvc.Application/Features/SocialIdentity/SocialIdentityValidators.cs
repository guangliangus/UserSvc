using FluentValidation;

namespace UserSvc.Application.Features.SocialIdentity;

/// <summary>
/// Shape checks for the third-party sign-in payloads. Failures become the <c>errors</c> dictionary
/// of a 400 ProblemDetails, which is a far more useful answer than the provider's own refusal to
/// a request that was never going to work.
/// <para>
/// <b>The upper bounds are the point of these validators, not the emptiness checks.</b> Every
/// value here is an opaque credential from a third party, and every one of them ends up either
/// hashed into a column or pasted into a URL. Without a ceiling, a client can post a megabyte of
/// junk and make this service pay for the HMAC, the encryption and the outbound request before
/// anything refuses it. The limits are generous - a Firebase ID token is routinely over a kilobyte
/// - and still bound the damage.
/// </para>
/// </summary>
public sealed class WechatSignInRequestValidator : AbstractValidator<WechatSignInRequest>
{
    public WechatSignInRequestValidator()
    {
        RuleFor(x => x.Code).NotEmpty().MaximumLength(256);
        RuleFor(x => x.State).NotEmpty().MaximumLength(1024);
    }
}

public sealed class WechatMiniSignInRequestValidator : AbstractValidator<WechatMiniSignInRequest>
{
    public WechatMiniSignInRequestValidator()
    {
        RuleFor(x => x.Code).NotEmpty().MaximumLength(256);

        // Optional: a mini-program sign-in without the phone step is the normal case, and the whole
        // phone branch is best effort.
        RuleFor(x => x.PhoneCode).MaximumLength(256);
    }
}

public sealed class LineSignInRequestValidator : AbstractValidator<LineSignInRequest>
{
    public LineSignInRequestValidator()
    {
        RuleFor(x => x.IdToken).NotEmpty().MaximumLength(4096);
        RuleFor(x => x.State).NotEmpty().MaximumLength(1024);
    }
}

public sealed class FirebaseSignInRequestValidator : AbstractValidator<FirebaseSignInRequest>
{
    public FirebaseSignInRequestValidator()
    {
        RuleFor(x => x.FirebaseIdToken).NotEmpty().MaximumLength(4096);

        // Deliberately only a length bound here. Whether the provider is one this deployment
        // accepts is the application service's answer, because it is configuration rather than
        // shape - and because the two refusals are different error codes the clients branch on.
        RuleFor(x => x.Provider).NotEmpty().MaximumLength(64);
    }
}

public sealed class ConfirmFirebaseBindingRequestValidator : AbstractValidator<ConfirmFirebaseBindingRequest>
{
    public ConfirmFirebaseBindingRequestValidator()
    {
        RuleFor(x => x.BindingToken).NotEmpty().MaximumLength(2048);

        // Confirm is deliberately unvalidated: false is a real answer, not a missing one.
    }
}
