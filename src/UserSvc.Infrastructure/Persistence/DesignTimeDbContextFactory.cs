using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace UserSvc.Infrastructure.Persistence;

/// <summary>
/// Used only by the <c>dotnet ef</c> tooling (the reference-SQL workflow of decision 14).
/// <para>
/// It keeps the DDL workflow <b>independent of the API project</b>, so the host never has to take
/// a design-time package. The connection string here only lets the tooling build the model; it
/// never opens a real connection — <c>dbcontext script</c> is entirely offline.
/// </para>
/// </summary>
public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<UserSvcDbContext>
{
    public UserSvcDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<UserSvcDbContext>()
            .UseNpgsql("Host=design-time;Database=usersvc;Username=design;Password=design")
            .UseSnakeCaseNamingConvention()
            .Options;

        return new UserSvcDbContext(options);
    }
}
