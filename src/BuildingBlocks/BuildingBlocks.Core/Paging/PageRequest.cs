namespace BuildingBlocks.Core.Paging;

/// <summary>Uniform pagination input. Bound from query string: ?page=1&amp;pageSize=20.</summary>
public sealed record PageRequest
{
    public const int MaxPageSize = 200;
    public const int DefaultPageSize = 20;

    public int Page { get; init; } = 1;
    public int PageSize { get; init; } = DefaultPageSize;

    public int Skip => (NormalizedPage - 1) * NormalizedPageSize;
    public int Take => NormalizedPageSize;

    public int NormalizedPage => Page < 1 ? 1 : Page;
    public int NormalizedPageSize => PageSize < 1 ? DefaultPageSize : Math.Min(PageSize, MaxPageSize);
}
