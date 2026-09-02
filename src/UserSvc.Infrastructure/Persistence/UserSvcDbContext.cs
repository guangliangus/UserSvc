using Microsoft.EntityFrameworkCore;
using UserSvc.Domain.Auth;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Feedback;
using UserSvc.Domain.Iam;
using UserSvc.Domain.Tenancy;
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

    /// <summary>
    /// The back-office (IAM) schema. A different bounded context from <see cref="Schema"/>, with no
    /// foreign key crossing between them: operator accounts and consumer accounts have separate
    /// lifecycles and separate id spaces, and the schema boundary is what keeps that separation
    /// enforceable rather than merely documented.
    /// </summary>
    public const string BackOfficeSchema = "iam";

    public DbSet<User> Users => Set<User>();

    public DbSet<UserIdentity> UserIdentities => Set<UserIdentity>();

    public DbSet<UserPasskey> UserPasskeys => Set<UserPasskey>();

    public DbSet<FeedbackSubmission> Feedback => Set<FeedbackSubmission>();

    public DbSet<FeedbackType> FeedbackTypes => Set<FeedbackType>();

    public DbSet<UserSession> UserSessions => Set<UserSession>();

    public DbSet<OutboxMessage> OutboxMessages => Set<OutboxMessage>();

    // --- Back-office (schema "iam") ---
    // A different bounded context from the consumer tables above. They share this context only so
    // that a role change and its audit entry commit together; no foreign key crosses between the
    // two schemas.

    public DbSet<BackendUser> BackendUsers => Set<BackendUser>();

    public DbSet<BackendIdentity> BackendIdentities => Set<BackendIdentity>();

    public DbSet<Role> Roles => Set<Role>();

    public DbSet<Permission> Permissions => Set<Permission>();

    public DbSet<Menu> Menus => Set<Menu>();

    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();

    public DbSet<RoleMenu> RoleMenus => Set<RoleMenu>();

    public DbSet<IamAuditLog> IamAuditLogs => Set<IamAuditLog>();

    public DbSet<TenantMember> TenantMembers => Set<TenantMember>();

    public DbSet<UserTenantRole> UserTenantRoles => Set<UserTenantRole>();

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
