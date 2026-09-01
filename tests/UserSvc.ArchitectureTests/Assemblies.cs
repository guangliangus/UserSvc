using System.Reflection;

namespace UserSvc.ArchitectureTests;

internal static class Assemblies
{
    public static readonly Assembly Domain = typeof(Domain.Users.User).Assembly;
    public static readonly Assembly Application = typeof(Application.Errors.AppException).Assembly;
    public static readonly Assembly Infrastructure = typeof(Infrastructure.DependencyInjection).Assembly;
    public static readonly Assembly Api = typeof(Api.Errors.AppExceptionHandler).Assembly;
}
