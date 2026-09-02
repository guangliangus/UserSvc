using UserSvc.Application.Errors;
using UserSvc.Application.Features.Localization;

namespace UserSvc.Api.Middleware;

/// <summary>
/// Translates the <c>detail</c> of a ProblemDetails response into the language the caller asked
/// for, from <see cref="ErrorMessageCatalog"/>, keyed on the <c>errorCode</c> already in the body.
/// <para>
/// <b>Why here.</b> <c>CustomizeProblemDetails</c> in <c>Program.cs</c> is the last thing to touch
/// the body on <b>every</b> path — the ones the exception handler maps and the ones it never sees,
/// such as an authentication challenge that a middleware answers by setting a status code and
/// returning. Translating at that one point covers all of them. The alternative, translating inside
/// the exception handler, would leave 401 and 403 — the two statuses clients hit most — in English
/// forever, and 401 is the response a person is most likely to actually read.
/// </para>
/// <para>
/// <b>What it deliberately does not touch.</b> <c>title</c> stays as written: it does not vary per
/// request for a given <c>type</c>, which is what lets a dashboard aggregate on it, and a title that
/// changed with the caller's language would fragment every one of those aggregates into seven.
/// The <c>errors</c> member keeps its English field messages too — those come out of
/// FluentValidation's own resources, which <c>Program.cs</c> pins to English on purpose so the error
/// contract does not depend on which machine answered.
/// </para>
/// <para>
/// <b>When it applies.</b> Only when the caller actually asked for a language, and only when the
/// catalogue has an entry for the code. Both conditions matter:
/// </para>
/// <list type="bullet">
/// <item><description>
/// A caller that asked for nothing keeps the sentence its throw site wrote. That is what let this
/// catalogue land without editing hundreds of throw sites, and it is why no existing response
/// changed shape or wording.
/// </description></item>
/// <item><description>
/// A code the catalogue does not carry also keeps its own sentence. The Go contract fell back to
/// echoing the code, which is right for a wire field a client branches on and wrong for a body a
/// person reads — <c>errorCode</c> already carries the code, so a <c>detail</c> reading
/// "ROLE_IN_USE" would be strictly less informative than the English sentence it replaced.
/// </description></item>
/// <item><description>
/// <see cref="ErrorCodes.NotConfigured"/> is not in the catalogue and must never be aliased into
/// it. Its detail names the configuration sections a deployment is missing, and that is the entire
/// value of the response to the operator reading it.
/// </description></item>
/// </list>
/// </summary>
public static class ProblemDetailLocalization
{
    /// <summary>
    /// Applies the translation in place. Call it from <c>CustomizeProblemDetails</c>, after the
    /// <c>errorCode</c> extension member has been filled — it is the key this reads.
    /// </summary>
    private static int _loadFailuresReported;

    public static void Apply(ProblemDetailsContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            Translate(context);
        }
        catch (Exception ex)
        {
            // The one place in this slice where a blanket catch is the correct answer rather than a
            // shrug. This runs on EVERY failure response, from inside the writer that is already
            // producing one: an exception escaping here would replace a perfectly good 400 or 401
            // with a broken response, and would do it for every error the service reports. The
            // untranslated sentence the throw site wrote is a complete answer, so translation is
            // the only thing allowed to fail - and it says so in the log rather than silently.
            Report(context, ex);
        }
    }

    private static void Translate(ProblemDetailsContext context)
    {
        var request = RequestContextAccessor.Of(context.HttpContext);

        if (!request.LocaleWasRequested)
        {
            return;
        }

        WarnOnceAboutBundlesThatWillNotLoad(context);

        if (!context.ProblemDetails.Extensions.TryGetValue("errorCode", out var raw)
            || raw is not string errorCode
            || errorCode.Length == 0)
        {
            return;
        }

        if (ErrorMessageCatalog.TryTranslate(errorCode, request.Locale, out var translated))
        {
            context.ProblemDetails.Detail = translated;
        }
    }

    /// <summary>
    /// The catalogue records a bundle it could not read instead of throwing, which is right - but a
    /// record nobody reads is a silent failure. The unit tests read it and fail the build on it,
    /// and this is the runtime half: the first request that would have been translated reports the
    /// packaging fault once, so a language quietly serving English in production leaves a trace.
    /// </summary>
    private static void WarnOnceAboutBundlesThatWillNotLoad(ProblemDetailsContext context)
    {
        if (ErrorMessageCatalog.LoadFailures.Count == 0
            || Interlocked.Exchange(ref _loadFailuresReported, 1) != 0)
        {
            return;
        }

        Logger(context)?.LogError(
            "{Count} error-message bundle(s) could not be read, so those languages are answering in "
            + "English: {Failures}",
            ErrorMessageCatalog.LoadFailures.Count,
            string.Join("; ", ErrorMessageCatalog.LoadFailures));
    }

    private static void Report(ProblemDetailsContext context, Exception exception)
    {
        try
        {
            Logger(context)?.LogError(
                exception,
                "Localizing the detail of a ProblemDetails response failed; the response keeps its "
                + "original wording.");
        }
        catch (Exception)
        {
            // Nothing left to do: we are inside the writer for a response that is already an error,
            // and even the logger is unavailable. Losing the log line is strictly better than
            // losing the response.
        }
    }

    private static ILogger? Logger(ProblemDetailsContext context) =>
        context.HttpContext.RequestServices?.GetService<ILoggerFactory>()
            ?.CreateLogger(typeof(ProblemDetailLocalization));
}
