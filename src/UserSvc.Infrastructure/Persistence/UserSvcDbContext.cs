using Microsoft.EntityFrameworkCore;
using UserSvc.Domain.Auth;
using UserSvc.Domain.Users;
using UserSvc.Infrastructure.Persistence.Outbox;

namespace UserSvc.Infrastructure.Persistence;

/// <summary>
/// The single persistence context (decision 15: EF Core only). For raw SQL use
/// <c>Database.SqlQuery&lt;T&gt;()</c> / <c>FromSql</c> / <c>ExecuteSql</c> — they run on the same
/// connection inside the same transaction, which is the main reason no second ORM is needed.
/// </summary>
public sealed class UserSvcDbContext(DbContextOptions<UserSvcDbContext> options) : DbContext(options)
{
    public const string Schema = "identity";

    public DbSet<User> Users => Set<User>();

    public DbSet<UserIdentity> UserIdentities => Set<UserIdentity>();

    public DbSet<UserSession> UserSessions => Set<UserSession>();

    public DbSet<OutboxMessage> OutboxMessages => Set<OutboxMessage>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema(Schema);

        // The team DDL convention uses SERIAL rather than GENERATED AS IDENTITY. Emit the same
        // thing here, or the "dotnet ef dbcontext script vs db/ scripts" CI gate reports a false
        // difference on every run (decision 14).
        modelBuilder.UseSerialColumns();
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(UserSvcDbContext).Assembly);

        // Decision 10: OpenIddict shares this context, so its four tables share our transaction and
        // our outbox interceptor. GUID keys, not the default string ones (37 bytes per foreign key)
        // and not int - OpenIddict writes two token rows per token request, so a 4-byte sequence
        // runs out long before the business does.
        modelBuilder.UseOpenIddict<Guid>();
        modelBuilder.ApplyOpenIddictConventions();
    }
}
