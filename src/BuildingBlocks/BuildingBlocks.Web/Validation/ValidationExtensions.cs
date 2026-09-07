using System.Reflection;
using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace BuildingBlocks.Web.Validation;

public static class ValidationExtensions
{
    /// <summary>Registers all validators in the given assemblies and enables auto-validation for controller actions.</summary>
    public static IServiceCollection AddMsvcValidation(this IServiceCollection services, params Assembly[] assemblies)
    {
        services.AddValidatorsFromAssemblies(assemblies, includeInternalTypes: true);
        services.Configure<MvcOptions>(options => options.Filters.Add<AutoValidationFilter>());
        return services;
    }
}
