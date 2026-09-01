using FluentValidation;
using Microsoft.AspNetCore.Mvc.Filters;

namespace UserSvc.Api.Filters;

/// <summary>
/// Runs any registered FluentValidation validator for the action arguments and throws
/// <see cref="ValidationException"/> on failure, which <see cref="Errors.AppExceptionHandler"/>
/// turns into the <c>errors</c> dictionary of a 400 ProblemDetails.
/// <para>Decision 05: cross-cutting logic like this rides on filters; no mediator pipeline needed.</para>
/// </summary>
public sealed class ValidationFilter(IServiceProvider services) : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        foreach (var argument in context.ActionArguments.Values)
        {
            if (argument is null)
            {
                continue;
            }

            var validatorType = typeof(IValidator<>).MakeGenericType(argument.GetType());
            if (services.GetService(validatorType) is not IValidator validator)
            {
                continue;
            }

            var validationContext = new ValidationContext<object>(argument);
            var result = await validator.ValidateAsync(validationContext, context.HttpContext.RequestAborted);

            if (!result.IsValid)
            {
                throw new ValidationException(result.Errors);
            }
        }

        await next();
    }
}
