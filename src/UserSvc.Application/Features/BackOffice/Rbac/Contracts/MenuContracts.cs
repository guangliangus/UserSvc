namespace UserSvc.Application.Features.BackOffice.Rbac.Contracts;

/// <summary>The menu tree, roots first.</summary>
public sealed record MenuTreeResponse
{
    public IReadOnlyList<MenuTreeNodeResponse> Items { get; init; } = [];
}

/// <summary>One node of the menu tree, with the permission points that hang off it.</summary>
public sealed record MenuTreeNodeResponse
{
    public int Id { get; init; }

    public string Code { get; init; } = string.Empty;

    public int? ParentId { get; init; }

    /// <summary>Localised names by locale. Always present, possibly empty - the client picks its
    /// own locale and its own fallback.</summary>
    public IReadOnlyDictionary<string, string> Name { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    public string? Path { get; init; }

    public string? Icon { get; init; }

    public int SortOrder { get; init; }

    /// <summary>Which tenant types this menu declares itself for. Echoed and editable; it does
    /// <b>not</b> narrow this response.</summary>
    public IReadOnlyList<string> Audience { get; init; } = [];

    public string Status { get; init; } = string.Empty;

    /// <summary>Always an array; empty on the per-user sidebar tree, which carries no points.</summary>
    public IReadOnlyList<MenuPermissionResponse> Permissions { get; init; } = [];

    public IReadOnlyList<MenuTreeNodeResponse> Children { get; init; } = [];
}

/// <summary>A permission point as it appears under its menu.</summary>
public sealed record MenuPermissionResponse
{
    public int Id { get; init; }

    public string Code { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    public string Status { get; init; } = string.Empty;
}

/// <summary>One menu row, flat - the shape create and edit answer with.</summary>
public sealed record MenuResponse
{
    public int Id { get; init; }

    public string Code { get; init; } = string.Empty;

    public int? ParentId { get; init; }

    public IReadOnlyDictionary<string, string> Name { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    public string? Path { get; init; }

    public string? Icon { get; init; }

    public int SortOrder { get; init; }

    public IReadOnlyList<string> Audience { get; init; } = [];

    public string Status { get; init; } = string.Empty;
}

/// <summary>Register a menu.</summary>
public sealed record CreateMenuRequest
{
    public string Code { get; init; } = string.Empty;

    public int? ParentId { get; init; }

    /// <summary>At least one locale is required - a menu nobody can read a label for is not a menu.</summary>
    public IReadOnlyDictionary<string, string> Name { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    public string? Path { get; init; }

    public string? Icon { get; init; }

    public int SortOrder { get; init; }

    /// <summary>Empty means all three tenant types.</summary>
    public IReadOnlyList<string> Audience { get; init; } = [];

    /// <summary>Empty means ACTIVE.</summary>
    public string Status { get; init; } = string.Empty;
}

/// <summary>
/// Edit a menu. <b>Code and parent are deliberately absent</b>: the code is baked into every grant
/// and into the front-end sidebar, and moving a node re-parents a whole subtree of grants behind the
/// operator's back.
/// </summary>
public sealed record UpdateMenuRequest
{
    public IReadOnlyDictionary<string, string> Name { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    public string? Path { get; init; }

    public string? Icon { get; init; }

    public int SortOrder { get; init; }

    public IReadOnlyList<string> Audience { get; init; } = [];

    public string Status { get; init; } = string.Empty;
}
