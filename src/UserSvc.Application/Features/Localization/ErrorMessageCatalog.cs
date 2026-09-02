using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Text.Json;
using UserSvc.Application.Errors;

namespace UserSvc.Application.Features.Localization;

/// <summary>
/// The user-facing sentence for an error code, in each of the seven supported locales.
/// <para>
/// <b>It is keyed by <see cref="ErrorCodes"/> values, and that is the whole design.</b> Those
/// values are the client contract and are add-only, which makes them the one identifier stable
/// enough to hang translations off. Because the key is the code rather than the message, this
/// catalogue translates the <c>detail</c> of a ProblemDetails response without a single throw site
/// changing — and there are hundreds of them, every one of which writes English prose inline.
/// The API layer's exception handler already separates <c>title</c> (stable, aggregatable, never
/// translated) from <c>detail</c> (the sentence a person reads); <c>detail</c> is the seam and this
/// is what plugs into it.
/// </para>
/// <para>
/// <b>Nothing here ever throws.</b> The Go original panicked at package init on a missing or
/// unparseable bundle, which is the right shape for Go and the wrong one here: this catalogue is
/// consulted on every failure response, so a throw during initialisation would turn one bad JSON
/// file into a service that cannot report any error at all — the widest possible blast radius, and
/// exactly what this repository's failure-isolation rule exists to prevent. A bundle that cannot be
/// read is recorded in <see cref="LoadFailures"/> and leaves its language untranslated.
/// </para>
/// <para>
/// That is not a hole, because the bundles are embedded resources compiled into this assembly: they
/// cannot rot after the build, so the only way to produce one is a packaging mistake — and the
/// coverage test in <c>tests/UserSvc.UnitTests/Localization</c> fails the build on it. Failing in CI
/// beats failing in production.
/// </para>
/// </summary>
public static class ErrorMessageCatalog
{
    /// <summary>
    /// Codes this service emits that the ported bundles have no entry for, mapped onto the entry
    /// that says the same thing. Each one is a judgement call, so each one is listed individually
    /// rather than derived.
    /// <para>
    /// <see cref="ErrorCodes.NotConfigured"/> is deliberately <b>absent</b>: its detail carries the
    /// names of the configuration sections a deployment is missing, which is the entire value of
    /// that response to the operator reading it. Replacing it with a translated sentence would send
    /// them to read code instead of secrets.
    /// </para>
    /// </summary>
    private static readonly FrozenDictionary<string, string> Aliases =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // The commonest failure in the service, and the Go bundles never had a code for it
            // because Go reported field errors one code at a time. BAD_REQUEST is the same
            // instruction to the user: check what you sent and try again.
            [ErrorCodes.ValidationFailed] = ErrorCodes.BadRequest,

            // Both mean "this credential is finished, sign in again", which is what INVALID_TOKEN
            // says. Neither existed in Go: session revocation was a jti blacklist that reported
            // INVALID_TOKEN, and replay detection is new here.
            [ErrorCodes.SessionRevoked] = ErrorCodes.InvalidToken,
            [ErrorCodes.RefreshTokenReplayed] = ErrorCodes.InvalidToken,

            [ErrorCodes.SessionNotFound] = ErrorCodes.NotFound,

            // A pure spelling divergence, and the .NET spelling cannot be corrected: ErrorCodes is
            // add-only, so the published constant stays ROLE_NOT_GLOBALLY_ASSIGNABLE while the
            // ported bundles are keyed ROLE_NOT_GLOBAL_ASSIGNABLE. Aliasing is how both survive.
            [ErrorCodes.RoleNotGloballyAssignable] = "ROLE_NOT_GLOBAL_ASSIGNABLE",
        }.ToFrozenDictionary(StringComparer.Ordinal);

    private static readonly Lazy<LoadedCatalog> Loaded =
        new(Load, LazyThreadSafetyMode.ExecutionAndPublication);

    private const string ResourcePrefix = "UserSvc.Application.Features.Localization.Locales.";

    /// <summary>
    /// Every code any bundle carries, and the locales each one covers. It exists for the coverage
    /// test: adding a language has to make every existing code fail until it is translated, and
    /// that needs the catalogue to be enumerable.
    /// </summary>
    public static IReadOnlyDictionary<string, FrozenDictionary<string, string>> All => Loaded.Value.Catalog;

    /// <summary>
    /// The bundles that could not be read, each as <c>"resource: reason"</c>. Empty in every build
    /// that packaged its resources correctly, which is what the coverage test asserts.
    /// </summary>
    public static IReadOnlyList<string> LoadFailures => Loaded.Value.Failures;

    /// <summary>
    /// The message for <paramref name="code"/> in <paramref name="locale"/>.
    /// <para>
    /// Fallback chain, verbatim from the Go contract: normalized locale, then English, then the code
    /// itself. Echoing the code is deliberate — a client that branches on the message still gets
    /// something deterministic — but it is the reason the ProblemDetails seam uses
    /// <see cref="TryTranslate"/> instead: a response body reading <c>"ROLE_IN_USE"</c> where a
    /// sentence belongs is worse than the English sentence the throw site already wrote.
    /// </para>
    /// </summary>
    public static string Translate(string code, string? locale) =>
        TryTranslate(code, locale, out var message) ? message : code;

    /// <summary>
    /// The message for <paramref name="code"/>, or <see langword="false"/> when this catalogue has
    /// nothing to say about it. Falls back from the requested locale to English, never to the code.
    /// </summary>
    public static bool TryTranslate(string code, string? locale, [NotNullWhen(true)] out string? message)
    {
        message = null;

        if (string.IsNullOrEmpty(code))
        {
            return false;
        }

        var key = Aliases.TryGetValue(code, out var alias) ? alias : code;

        if (!Loaded.Value.Catalog.TryGetValue(key, out var byLocale))
        {
            return false;
        }

        var normalized = SupportedLocales.Normalize(locale);

        if (byLocale.TryGetValue(normalized, out var localized) && localized.Length > 0)
        {
            message = localized;
            return true;
        }

        if (byLocale.TryGetValue(SupportedLocales.Default, out var english) && english.Length > 0)
        {
            message = english;
            return true;
        }

        return false;
    }

    /// <summary>Whether the catalogue can answer for this code, alias table included.</summary>
    public static bool Covers(string code) =>
        Loaded.Value.Catalog.ContainsKey(Aliases.TryGetValue(code, out var alias) ? alias : code);

    /// <summary>The alias table, for the test that pins every target actually exists.</summary>
    public static IReadOnlyDictionary<string, string> AliasedCodes => Aliases;

    /// <summary>
    /// Reads every embedded bundle into one <c>code -&gt; locale -&gt; message</c> map. A bundle
    /// that will not open or will not parse is skipped and named in the failure list; see the type
    /// remarks for why it is not allowed to throw.
    /// </summary>
    private static LoadedCatalog Load()
    {
        var catalog = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
        var failures = new List<string>();

        // The whole body is guarded, not just each bundle. This runs inside a Lazy, so an escaping
        // exception would be CACHED and rethrown on every subsequent access - one unexpected
        // reflection or IO failure would permanently turn a catalogue lookup into a throw, on a
        // path every failure response crosses. An empty catalogue simply leaves every detail in
        // the language its throw site wrote.
        try
        {
            Fill(catalog, failures);
        }
        catch (Exception ex)
        {
            failures.Add($"{ResourcePrefix}*: the bundles could not be enumerated: {ex.Message}");
        }

        return new LoadedCatalog(
            catalog.ToFrozenDictionary(
                entry => entry.Key,
                entry => entry.Value.ToFrozenDictionary(StringComparer.Ordinal),
                StringComparer.Ordinal),
            failures);
    }

    private static void Fill(
        Dictionary<string, Dictionary<string, string>> catalog, List<string> failures)
    {
        var assembly = typeof(ErrorMessageCatalog).Assembly;

        foreach (var resource in assembly.GetManifestResourceNames())
        {
            if (!resource.StartsWith(ResourcePrefix, StringComparison.Ordinal)
                || !resource.EndsWith(".json", StringComparison.Ordinal))
            {
                continue;
            }

            var locale = resource[ResourcePrefix.Length..^".json".Length];
            var messages = Read(assembly, resource, out var failure);

            if (messages is null)
            {
                failures.Add($"{resource}: {failure}");
                continue;
            }

            foreach (var (code, message) in messages)
            {
                if (!catalog.TryGetValue(code, out var byLocale))
                {
                    byLocale = new Dictionary<string, string>(StringComparer.Ordinal);
                    catalog[code] = byLocale;
                }

                byLocale[locale] = message;
            }
        }
    }

    private static Dictionary<string, string>? Read(Assembly assembly, string resource, out string failure)
    {
        failure = string.Empty;

        try
        {
            using var stream = assembly.GetManifestResourceStream(resource);

            if (stream is null)
            {
                failure = "the embedded resource could not be opened";
                return null;
            }

            var messages = JsonSerializer.Deserialize<Dictionary<string, string>>(stream);

            if (messages is null)
            {
                failure = "the bundle deserialized to nothing";
            }

            return messages;
        }
        catch (Exception ex)
        {
            // Every exception, not only JsonException: a bundle whose value is a number raises
            // JsonException, but an unreadable resource stream raises IOException and a resource
            // the compiler recorded but did not embed raises neither. All three mean the same
            // thing here - this language has no text - and none of them may reach a caller that is
            // in the middle of writing an error response.
            failure = "the bundle could not be read: " + ex.Message;
            return null;
        }
    }

    private sealed record LoadedCatalog(
        FrozenDictionary<string, FrozenDictionary<string, string>> Catalog,
        IReadOnlyList<string> Failures);
}
