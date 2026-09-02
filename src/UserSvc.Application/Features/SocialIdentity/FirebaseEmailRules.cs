namespace UserSvc.Application.Features.SocialIdentity;

/// <summary>
/// Which addresses coming out of a Firebase sign-in may be treated as an email the person actually
/// owns and can be found by.
/// <para>
/// Pure computation over a string, so it lives beside the feature rather than behind a port.
/// </para>
/// </summary>
public static class FirebaseEmailRules
{
    /// <summary>
    /// Apple's "Hide My Email" relay domain. An address under it is a per-app proxy Apple minted
    /// for this one relying party.
    /// </summary>
    public const string AppleProxyEmailDomain = "@privaterelay.appleid.com";

    /// <summary>
    /// The real, reusable address from a Firebase sign-in, or empty when there is none.
    /// <para>
    /// <b>An Apple private-relay address is reported as absent, not as an address.</b> It is unique
    /// to this app, so it can never match another account and the user can never sign in elsewhere
    /// with it. Persisting one as an email identity would create a login identifier nobody can
    /// type, and matching one against existing accounts would always miss - the two failures this
    /// rule exists to prevent.
    /// </para>
    /// <para>
    /// <b>It deliberately does not consult <c>email_verified</c>.</b> That looks like an omission
    /// and is not: the address here comes from a provider that authenticated the user moments ago,
    /// and several providers (Apple in particular, for a relay address, and Facebook for accounts
    /// created before it started asserting the flag) leave the claim false on addresses they are
    /// perfectly certain about. Requiring it would push those users into creating a duplicate
    /// account beside the one they already have. The unit tests pin this behaviour precisely
    /// because it reads like a bug.
    /// </para>
    /// </summary>
    public static string UsableEmail(string? email)
    {
        var trimmed = email?.Trim() ?? string.Empty;

        return trimmed.Length == 0 || IsAppleProxyEmail(trimmed) ? string.Empty : trimmed;
    }

    /// <summary>Whether the address is one of Apple's per-app relay addresses.</summary>
    public static bool IsAppleProxyEmail(string? email) =>
        email?.Trim().EndsWith(AppleProxyEmailDomain, StringComparison.OrdinalIgnoreCase) == true;
}
