namespace BuildingBlocks.Core.Paging;

/// <summary>Uniform pagination envelope for list endpoints (the only wrapping the API layer does).</summary>
public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Page, int PageSize, long TotalCount)
{
    public long TotalPages => PageSize <= 0 ? 0 : (TotalCount + PageSize - 1) / PageSize;
    public bool HasNextPage => Page < TotalPages;
}
