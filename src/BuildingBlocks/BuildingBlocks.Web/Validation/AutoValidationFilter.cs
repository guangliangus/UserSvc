using System.Collections.Concurrent;
using FluentValidation;
using Microsoft.AspNetCore.Mvc.Filters;

namespace BuildingBlocks.Web.Validation;

/// <summary>
/// Runs every registered IValidator&lt;T&gt; against matching action arguments and throws a
/// FluentValidation ValidationException on failure (mapped centrally to a 400 ProblemDetails).
/// Replaces the deprecated FluentValidation.AspNetCore auto-validation package.
/// </summary>
public sealed class AutoValidationFilter : IAsyncActionFilter
{
    // Closed IValidator<T> per argument type — MakeGenericType is not free on hot paths.
    private static readonly ConcurrentDictionary<Type, Type> ValidatorTypes = new();

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        List<FluentValidation.Results.ValidationFailure>? failures = null;

        foreach (var argument in context.ActionArguments.Values)
        {
            if (argument is null)
            {
                continue;
            }

            var validatorType = ValidatorTypes.GetOrAdd(
                argument.GetType(), static t => typeof(IValidator<>).MakeGenericType(t));
            if (context.HttpContext.RequestServices.GetService(validatorType) is not IValidator validator)
            {
                continue;
            }

            var result = await validator.ValidateAsync(
                new ValidationContext<object>(argument),
                context.HttpContext.RequestAborted);
            if (!result.IsValid)
            {
                (failures ??= []).AddRange(result.Errors);
            }
        }

        if (failures is { Count: > 0 })
        {
            throw new ValidationException(failures);
        }

        await next();
    }
}
