namespace UserSvc.Application.Features.Localization;

/// <summary>Which header answered a request's language question.</summary>
public enum LocaleSource
{
    /// <summary>Nobody asked; English by default.</summary>
    Default = 0,

    /// <summary><c>X-Language</c>: an explicit product decision by a client that knows its own UI
    /// language.</summary>
    LanguageHeader = 1,

    /// <summary><c>Accept-Language</c>: the browser passing on the operating system's guess.</summary>
    AcceptLanguage = 2,
}

/// <summary>
/// The language a request will be answered in, and whether the client actually asked for it.
/// </summary>
/// <param name="Locale">One of <see cref="SupportedLocales.Codes"/>. Always populated.</param>
/// <param name="WasRequested">Whether the client asked for a language this service has text in, as
/// opposed to asking for nothing (or for Klingon) and being defaulted to English. Error
/// <c>detail</c> is translated only when this is true, which is what keeps every response to a
/// caller that asked for nothing byte-identical.</param>
/// <param name="Source">Which header answered, for <c>Content-Language</c> and for logs.</param>
public sealed record NegotiatedLocale(string Locale, bool WasRequested, LocaleSource Source)
{
    /// <summary>What a request that asked for nothing gets.</summary>
    public static NegotiatedLocale Default { get; } =
        new(SupportedLocales.Default, false, LocaleSource.Default);
}

/// <summary>
/// Resolves a request's language from the two headers that can carry one.
/// <para>
/// It lives in the application layer rather than beside the middleware that calls it for one
/// reason: <b>the precedence between the two headers is the whole decision</b>, and it deserves
/// tests that do not need an <c>HttpContext</c>. The middleware's job is reduced to reading two
/// strings off the request and handing them here.
/// </para>
/// <para>
/// <c>X-Language</c> wins whenever it names a language this service has text for: it is a client
/// stating which language its own interface is in, where <c>Accept-Language</c> is a browser
/// forwarding an operating-system preference the user may never have thought about. An
/// <c>X-Language</c> this service has no text for falls through to <c>Accept-Language</c> rather
/// than to English - a Danish app asking for <c>Accept-Language: en</c> is better served in English
/// than defaulted there by accident.
/// </para>
/// </summary>
public static class LocaleNegotiation
{
    /// <summary>
    /// The locale for a request carrying these two header values. Never returns null, and never
    /// reports <see cref="NegotiatedLocale.WasRequested"/> for a language it had to guess.
    /// </summary>
    public static NegotiatedLocale Resolve(string? languageHeader, string? acceptLanguageHeader)
    {
        if (SupportedLocales.TryNormalize(languageHeader, out var explicitLocale))
        {
            return new NegotiatedLocale(explicitLocale, true, LocaleSource.LanguageHeader);
        }

        return AcceptLanguageNegotiator.Negotiate(acceptLanguageHeader) is { } negotiated
            ? new NegotiatedLocale(negotiated, true, LocaleSource.AcceptLanguage)
            : NegotiatedLocale.Default;
    }
}
