namespace UserSvc.Application.Features.BackOffice.TestWhitelist;

/// <summary>
/// Paging arithmetic for a list that is read whole and sliced in memory.
/// <para>
/// It is in memory on purpose. The whitelist holds a couple of dozen ids, the listing needs the
/// true total anyway, and hydrating a page costs two batch reads whatever the page size - so paging
/// here is a convenience for the screen rather than a scale mechanism, and pushing it into SQL
/// would buy a second query for the count and nothing else.
/// </para>
/// <para>
/// Pure functions, so they are not a port and the tests use the real thing.
/// </para>
/// </summary>
public static class TestWhitelistPaging
{
    /// <summary>The default page size. Mirrors the rest of the back office so the whole product
    /// shares one paging idiom.</summary>
    public const int DefaultPageSize = 20;

    /// <summary>The largest page anyone may ask for. It bounds how many identifiers one request
    /// decrypts, which is the reason it is a hard cap rather than a suggestion.</summary>
    public const int MaxPageSize = 100;

    /// <summary>
    /// Brings a requested page and size into range: a page below one becomes the first page, a
    /// non-positive size becomes the default, and an oversized one is clamped.
    /// <para>
    /// Corrected rather than refused, deliberately. The alternative answers a paging query with a
    /// validation error, which is a worse experience than showing the first page - and the numbers
    /// the response echoes back are the corrected ones, so a client cannot mistake what it got.
    /// </para>
    /// </summary>
    public static (int Page, int PageSize) Normalize(int page, int pageSize) =>
        (page < 1 ? 1 : page, pageSize switch
        {
            <= 0 => DefaultPageSize,
            > MaxPageSize => MaxPageSize,
            _ => pageSize,
        });

    /// <summary>
    /// The requested slice of an ascending id list.
    /// <para>
    /// An out-of-range page yields an empty slice rather than an error: a listing whose last member
    /// was just removed should render as empty, not fail.
    /// </para>
    /// </summary>
    public static IReadOnlyList<int> Slice(IReadOnlyList<int> ids, int page, int pageSize)
    {
        ArgumentNullException.ThrowIfNull(ids);

        if (page <= 0 || pageSize <= 0)
        {
            return [];
        }

        // Widened deliberately: a client is free to ask for page 2147483647, and computing the
        // offset in int would overflow to a negative number that Skip refuses with an exception -
        // a 500 for a query whose correct answer is an empty page.
        var offset = ((long)page - 1) * pageSize;

        return offset >= ids.Count ? [] : [.. ids.Skip((int)offset).Take(pageSize)];
    }

    /// <summary>The page count for a total at this page size; zero when there is nothing to
    /// page.</summary>
    public static int TotalPages(int total, int pageSize) =>
        pageSize <= 0 || total <= 0 ? 0 : ((total - 1) / pageSize) + 1;
}
