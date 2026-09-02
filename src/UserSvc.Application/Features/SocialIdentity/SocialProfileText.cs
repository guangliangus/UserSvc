namespace UserSvc.Application.Features.SocialIdentity;

/// <summary>
/// The two string decisions every third-party sign-in has to make: what to call an account nobody
/// has named, and how much of an identifier may appear in a response.
/// </summary>
public static class SocialProfileText
{
    /// <summary>
    /// Shown when a provider gave us neither a name nor an address to derive one from. Kept
    /// identical to <c>RegistrationAppService</c>'s default so an account created by signing in
    /// with WeChat is indistinguishable from one created at the sign-up form.
    /// </summary>
    public const string DefaultNickname = "Lion Travel Member";

    /// <summary>
    /// Provider display name, then the local part of the address, then the default. That order is
    /// the original's and it is the right one: a name the person chose beats a string scraped out
    /// of their address, and both beat a generic label.
    /// </summary>
    public static string Nickname(string? providerName, string? email)
    {
        if (!string.IsNullOrWhiteSpace(providerName))
        {
            return providerName.Trim();
        }

        var address = email?.Trim() ?? string.Empty;
        var separator = address.IndexOf('@', StringComparison.Ordinal);
        if (separator > 0)
        {
            return address[..separator];
        }

        return DefaultNickname;
    }

    /// <summary>
    /// Enough of an identifier for a person to recognise their own, not enough for anyone else to
    /// use it.
    /// <para>
    /// The sign-in responses list the account's login identities, and an anonymous endpoint that
    /// echoed those in the clear would hand the full set to whoever resolved the account - which,
    /// on the LINE email-merge path, is a caller who proved control of a LINE account and nothing
    /// else. Masked here, in the clear at <c>/user/profile</c> behind a token: the same information
    /// with a real credential in front of it.
    /// </para>
    /// </summary>
    public static string Mask(string identityType, string? identifier)
    {
        var value = identifier?.Trim() ?? string.Empty;
        if (value.Length == 0)
        {
            return string.Empty;
        }

        var separator = value.IndexOf('@', StringComparison.Ordinal);
        if (separator > 0)
        {
            var local = value[..separator];
            var domain = value[separator..];
            var keep = Math.Min(3, local.Length);

            return string.Concat(local.AsSpan(0, keep), "***", domain);
        }

        // Everything that is not an address - phone numbers, and the opaque provider subjects that
        // are the whole identifier for a WeChat or LINE identity - is masked from the left, because
        // the informative end of an openid is nowhere in particular and the informative end of a
        // phone number is the last few digits.
        if (value.Length <= 4)
        {
            return new string('*', value.Length);
        }

        var tail = value[^4..];
        return identityType == Domain.Users.IdentityTypes.Phone && value.Length > 7
            ? value[..3] + "****" + tail
            : "****" + tail;
    }
}
