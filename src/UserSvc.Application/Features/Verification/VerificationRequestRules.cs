using System.Text.RegularExpressions;
using UserSvc.Application.Errors;
using UserSvc.Domain.Verification;

namespace UserSvc.Application.Features.Verification;

/// <summary>
/// Payload validation for the two verification endpoints.
/// <para>
/// It is written by hand rather than as a FluentValidation validator, and the reason is the error
/// contract: a validator produces one <c>VALIDATION_FAILED</c> with a field dictionary, while these
/// endpoints promise distinct machine-readable codes - <c>INVALID_PHONE_FORMAT</c> and
/// <c>INVALID_EMAIL_FORMAT</c> - that clients already branch on. Keeping the rules here also keeps
/// them <b>after</b> the rate-limit check, which a global action filter could not do.
/// </para>
/// </summary>
public static partial class VerificationRequestRules
{
    /// <summary>
    /// Accepts E.164 with or without the plus, and bare mainland-China mobile numbers, which is
    /// what the mobile clients send today. Anchored and free of nested quantifiers, so it cannot be
    /// made to backtrack.
    /// </summary>
    [GeneratedRegex(@"^(\+?[1-9]\d{1,14}|1[3-9]\d{9})$", RegexOptions.CultureInvariant)]
    private static partial Regex PhonePattern();

    /// <summary>
    /// Deliberately permissive: the only address that truly validates is one that receives the
    /// code, so this rejects obvious typos and leaves the real check to delivery.
    /// </summary>
    [GeneratedRegex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", RegexOptions.CultureInvariant)]
    private static partial Regex EmailPattern();

    /// <summary>Validates a send request in the order the client should fix it: presence, then
    /// vocabulary, then the shape of the target.</summary>
    public static void Validate(SendVerificationCodeRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        RequireTarget(request.Target);
        RequireTargetType(request.TargetType);
        RequirePurpose(request.Purpose);
        RequireWellFormedTarget(request.TargetType, request.Target);
    }

    /// <summary>Validates a verify request. There is no target-format check here on purpose: a
    /// malformed target simply matches no code row, and saying so twice adds nothing.</summary>
    public static void Validate(VerifyCodeRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        RequireTarget(request.Target);

        if (string.IsNullOrWhiteSpace(request.Code))
        {
            throw new BadRequestException(ErrorCodes.BadRequest, "The verification code is required.");
        }

        RequirePurpose(request.Purpose);
    }

    private static void RequireTarget(string target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            throw new BadRequestException(ErrorCodes.BadRequest, "A target phone number or email address is required.");
        }
    }

    private static void RequireTargetType(string targetType)
    {
        if (!VerificationTargetTypes.IsKnown(targetType))
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest,
                $"The target type must be '{VerificationTargetTypes.Email}' or '{VerificationTargetTypes.Phone}'.");
        }
    }

    private static void RequirePurpose(string purpose)
    {
        if (!VerificationPurposes.IsKnown(purpose))
        {
            throw new BadRequestException(ErrorCodes.BadRequest, "The verification purpose is not one this service issues codes for.");
        }
    }

    private static void RequireWellFormedTarget(string targetType, string target)
    {
        if (targetType == VerificationTargetTypes.Phone && !PhonePattern().IsMatch(target))
        {
            throw new BadRequestException(ErrorCodes.InvalidPhoneFormat, "The phone number is not a valid number.");
        }

        if (targetType == VerificationTargetTypes.Email && !EmailPattern().IsMatch(target))
        {
            throw new BadRequestException(ErrorCodes.InvalidEmailFormat, "The email address is not a valid address.");
        }
    }
}
