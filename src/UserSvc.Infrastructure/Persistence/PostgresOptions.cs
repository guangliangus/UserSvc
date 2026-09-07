using System.ComponentModel.DataAnnotations;

namespace UserSvc.Infrastructure.Persistence;

/// <summary>
/// Bound from "Postgres". Taken from the template's BuildingBlocks.Data as a file rather than as
/// the project: that project also brings an audit interceptor and an <c>Entity</c> base class
/// whose semantics differ from this service's (docs/architecture.md, "BuildingBlocks"). Every
/// value has a working default, so the section may be absent.
/// </summary>
public sealed class PostgresOptions
{
    public const string SectionName = "Postgres";

    /// <summary>Key under ConnectionStrings to use.</summary>
    [Required(AllowEmptyStrings = false)]
    public string ConnectionStringName { get; set; } = "Default";

    /// <summary>Transient-failure retry attempts (EF execution strategy).</summary>
    [Range(0, 20)]
    public int MaxRetryCount { get; set; } = 5;

    [Range(1, 300)]
    public int MaxRetryDelaySeconds { get; set; } = 30;

    /// <summary>
    /// Per-statement timeout. Without one a statement holds its connection for as long as
    /// PostgreSQL lets it, and a pool of stuck connections is how one slow query becomes an outage.
    /// </summary>
    [Range(1, 3600)]
    public int CommandTimeoutSeconds { get; set; } = 30;
}
