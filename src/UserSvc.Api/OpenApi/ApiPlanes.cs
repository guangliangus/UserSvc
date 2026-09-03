using Microsoft.AspNetCore.Mvc.ApiExplorer;

namespace UserSvc.Api.OpenApi;

/// <summary>
/// Which identity plane a route belongs to, decided from the route itself.
/// <para>
/// <b>The prefix is the whole rule.</b> <c>/api/v{n}/back-office/**</c> is the back office and
/// everything else is the consumer app — which is why the five back-office endpoints that used to
/// live under <c>/api/v{n}/auth/</c> were moved. While the two planes shared that prefix, "which
/// plane is this route on" could only be answered by reading the controller, and the answer was got
/// wrong: <c>RbacController</c> and <c>MenuController</c> shipped with a bare <c>[Authorize]</c>,
/// and a consumer access token read the entire role and permission catalogue and created a role.
/// </para>
/// <para>
/// <c>/connect/**</c> is deliberately <b>neither</b>. The token endpoint issues credentials for both
/// planes — the device grant for consumers, the sign-in ticket grants for the back office — so it
/// belongs in both documents. Filing it under one plane would leave the other's generated client
/// unable to obtain a token at all.
/// </para>
/// </summary>
internal static class ApiPlanes
{
    /// <summary>The path segment that marks the back-office plane.</summary>
    public const string BackOfficeSegment = "back-office";

    /// <summary>Prefix of the OpenAPI document that carries the back-office plane. The suffix is
    /// the API version, so the document name reads <c>back-office-v1</c>.</summary>
    public const string BackOfficeDocumentPrefix = "back-office-";

    /// <summary>The back-office document name for one API version group, for example
    /// <c>v1</c> to <c>back-office-v1</c>.</summary>
    public static string BackOfficeDocument(string versionGroupName) =>
        BackOfficeDocumentPrefix + versionGroupName;

    /// <summary>Whether a document name is a back-office one, and which version it carries.</summary>
    public static bool IsBackOfficeDocument(string documentName, out string versionGroupName)
    {
        if (documentName.StartsWith(BackOfficeDocumentPrefix, StringComparison.Ordinal))
        {
            versionGroupName = documentName[BackOfficeDocumentPrefix.Length..];
            return true;
        }

        versionGroupName = string.Empty;
        return false;
    }

    /// <summary>
    /// Whether the route is on the back-office plane. Read off the relative path rather than the
    /// controller's namespace, because the path is what the policy, the client and the reader all
    /// see — a controller filed in the right folder but routed to the wrong prefix would otherwise
    /// be classified by the one signal nobody can check from outside.
    /// </summary>
    public static bool IsBackOffice(ApiDescription description) =>
        Segments(description) is [_, _, BackOfficeSegment, ..];

    /// <summary>Whether the route serves both planes and therefore belongs in both documents.</summary>
    public static bool IsShared(ApiDescription description) =>
        Segments(description) is ["connect", ..];

    /// <summary>
    /// The version group the route's path carries, for example <c>v1</c>, or empty for a
    /// version-neutral route such as the token endpoint. It is read from the path because
    /// <c>SubstituteApiVersionInUrl</c> has already written it there, which makes this the same
    /// string the document is named after.
    /// </summary>
    public static string VersionGroup(ApiDescription description) =>
        Segments(description) is ["api", var version, ..] ? version : string.Empty;

    private static string[] Segments(ApiDescription description) =>
        (description.RelativePath ?? string.Empty).Split('/', StringSplitOptions.RemoveEmptyEntries);
}
