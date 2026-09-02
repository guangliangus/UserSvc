namespace UserSvc.Application.Features.BackOffice.Rbac.Contracts;

/// <summary>Add a permission point to the catalogue.</summary>
public sealed record CreatePermissionRequest
{
    public string Code { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    public string Description { get; init; } = string.Empty;

    /// <summary>Grouping label for the catalogue page.</summary>
    public string Module { get; init; } = string.Empty;

    /// <summary>Null = a service-level point that never shows up in the tenant permission tree, and
    /// which only a platform role may be granted.</summary>
    public int? MenuId { get; init; }
}

/// <summary>Edit a permission point. Its code is not editable - it is what every grant refers to.</summary>
public sealed record UpdatePermissionRequest
{
    public string Name { get; init; } = string.Empty;

    public string Description { get; init; } = string.Empty;

    public string Module { get; init; } = string.Empty;

    /// <summary>ACTIVE or INACTIVE. INACTIVE is the soft delete.</summary>
    public string Status { get; init; } = string.Empty;

    /// <summary>Full replacement: null detaches the point from its menu and makes it
    /// service-level.</summary>
    public int? MenuId { get; init; }
}

/// <summary>A permission point as the catalogue renders it.</summary>
public sealed record PermissionResponse
{
    public int Id { get; init; }

    public string Code { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    public string Description { get; init; } = string.Empty;

    public string Module { get; init; } = string.Empty;

    public string Status { get; init; } = string.Empty;

    public int? MenuId { get; init; }
}
