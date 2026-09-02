namespace UserSvc.Api.Middleware;

/// <summary>
/// Prefix matching for request paths, on whole segments.
/// <para>
/// <b>The segment boundary is the whole point, and it is the same rule the locale normalizer
/// applies to language subtags.</b> A bare <c>StartsWith</c> makes <c>/health</c> match
/// <c>/healthcheck-admin</c> and <c>/metrics</c> match <c>/metrics-export</c> - which, for the
/// lists these prefixes serve, means silently exempting a real endpoint from the header gate or
/// from the trace header. Requiring the prefix to end where a segment ends removes the whole class
/// of lookalike.
/// </para>
/// </summary>
internal static class PathPrefix
{
    /// <summary>
    /// Whether <paramref name="path"/> is <paramref name="prefix"/> itself or sits underneath it.
    /// A trailing slash on either side is tolerated, because a configured prefix is written by hand.
    /// </summary>
    public static bool Matches(string path, string prefix)
    {
        var trimmed = prefix.AsSpan().TrimEnd('/');

        if (trimmed.IsEmpty)
        {
            return false;
        }

        if (!path.AsSpan().StartsWith(trimmed, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return path.Length == trimmed.Length || path[trimmed.Length] == '/';
    }
}
