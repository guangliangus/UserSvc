using Microsoft.EntityFrameworkCore;

namespace UserSvc.Infrastructure.Persistence;

/// <summary>
/// Drags OpenIddict's four tables into this codebase's naming and typing conventions.
/// <para>
/// None of it happens on its own. OpenIddict names its tables with an explicit
/// <c>ToTable("OpenIddictApplications")</c>, and an explicit table name is exactly what
/// EFCore.NamingConventions leaves alone — so without this the snake-case convention silently skips
/// them and <c>HasDefaultSchema("identity")</c> pulls quoted PascalCase tables into our own schema.
/// </para>
/// <para>
/// The column retyping is not cosmetic either: OpenIddict applies <c>HasMaxLength(50/100/150/…)</c>
/// to its string properties, which Npgsql renders as <c>character varying(n)</c>. The house rule is
/// <c>text</c> everywhere with length checks in code, and — more to the point — the CI gate that
/// diffs <c>dotnet ef dbcontext script</c> against <c>db/*.sql</c> compares the <b>model</b>, so
/// fixing the types only in the DDL would leave that gate reporting permanent drift.
/// </para>
/// </summary>
public static class OpenIddictModelConventions
{
    /// <summary>OpenIddict's tables live in their own schema: they are protocol plumbing, not part
    /// of the identity domain, and separating them keeps grants and backups independent.</summary>
    public const string Schema = "openiddict";

    private const string ModelNamespace = "OpenIddict.EntityFrameworkCore.Models";

    private static readonly Dictionary<string, string> TableNames = new(StringComparer.Ordinal)
    {
        ["OpenIddictApplications"] = "openiddict_applications",
        ["OpenIddictAuthorizations"] = "openiddict_authorizations",
        ["OpenIddictScopes"] = "openiddict_scopes",
        ["OpenIddictTokens"] = "openiddict_tokens",
    };

    /// <summary>Call after <c>UseOpenIddict&lt;Guid&gt;()</c> and after the local configurations,
    /// so the entity types actually exist on the model.</summary>
    public static ModelBuilder ApplyOpenIddictConventions(this ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            if (entityType.ClrType.Namespace?.StartsWith(ModelNamespace, StringComparison.Ordinal) != true)
            {
                continue;
            }

            entityType.SetSchema(Schema);

            var table = entityType.GetTableName();
            if (table is not null && TableNames.TryGetValue(table, out var renamed))
            {
                entityType.SetTableName(renamed);
            }

            foreach (var property in entityType.GetProperties())
            {
                if (property.ClrType != typeof(string))
                {
                    continue;
                }

                property.SetColumnType("text");
                property.SetMaxLength(null);
            }
        }

        return modelBuilder;
    }
}
